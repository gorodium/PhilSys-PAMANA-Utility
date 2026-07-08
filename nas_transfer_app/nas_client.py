import os
import posixpath
import stat
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import paramiko

from .config import DEFAULT_CHUNK_SIZE_MB, normalize_remote_path
from .packet_tools import PacketSearchResult


def remote_join(base, name):
    if base == "/":
        return "/" + name
    return posixpath.join(base, name)


def is_remote_dir(attrs):
    return stat.S_ISDIR(attrs.st_mode)


def is_remote_file(attrs):
    return stat.S_ISREG(attrs.st_mode)


@dataclass
class NasConnectionConfig:
    name: str
    host: str
    port: int
    username: str
    password: str


class NasClient:
    def __init__(self, config, chunk_size_mb=DEFAULT_CHUNK_SIZE_MB):
        self.config = config
        self.chunk_size = max(1, int(chunk_size_mb or DEFAULT_CHUNK_SIZE_MB)) * 1024 * 1024
        self.ssh = None
        self.sftp = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    @property
    def name(self):
        return self.config["name"]

    @property
    def profile_name(self):
        return self.config.get("profile_name", self.name)

    def connect(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=self.config["host"],
            port=self.config["port"],
            username=self.config["username"],
            password=self.config["password"],
            timeout=30,
            banner_timeout=30,
            auth_timeout=30,
        )
        transport = ssh.get_transport()
        if transport:
            transport.set_keepalive(30)
        self.ssh = ssh
        self.sftp = ssh.open_sftp()

    def close(self):
        for handle in (self.sftp, self.ssh):
            if handle:
                try:
                    handle.close()
                except Exception:
                    pass
        self.sftp = None
        self.ssh = None

    def test_connection(self):
        self.sftp.listdir_attr(".")

    def mkdir_p(self, remote_path):
        remote_path = normalize_remote_path(remote_path)
        if remote_path == "/":
            return

        current = ""
        for part in remote_path.strip("/").split("/"):
            current = remote_join(current or "/", part)
            try:
                attrs = self.sftp.stat(current)
                if not is_remote_dir(attrs):
                    raise RuntimeError(f"Path exists but is not a folder: {current}")
            except FileNotFoundError:
                self.sftp.mkdir(current)

    def path_exists(self, remote_path):
        """Return True if the remote path exists (file or directory)."""
        try:
            self.sftp.stat(remote_path)
            return True
        except FileNotFoundError:
            return False

    def list_dir_filenames(self, remote_path):
        """Return list of filenames inside a remote directory, or empty list if not accessible."""
        try:
            return [item.filename for item in self.sftp.listdir_attr(remote_path)]
        except Exception:
            return []

    def _check_ssh_exec_works(self):
        """Test once per connection whether SSH exec_command actually runs shell commands.
        Some NAS devices accept SSH connections but have restricted shells that don't execute
        arbitrary commands.  Returns True only if 'echo __test__' returns '__test__'."""
        if not hasattr(self, '_ssh_exec_ok'):
            try:
                _, stdout_ch, _ = self.ssh.exec_command("echo __philsys_test__", timeout=15)
                stdout_ch.channel.settimeout(15)
                result = stdout_ch.read().decode('utf-8', errors='replace').strip()
                self._ssh_exec_ok = (result == "__philsys_test__")
            except Exception:
                self._ssh_exec_ok = False
        return self._ssh_exec_ok


    def search_packets(self, packet_ids, root="/", max_results_per_packet=200, cancel_event=None, stop_when_all_found=False, progress_callback=None):
        root = normalize_remote_path(root)
        packet_keys = {packet.casefold(): packet for packet in packet_ids}
        counts = {packet.casefold(): 0 for packet in packet_ids}
        results = []

        def _try_ssh_find():
            """Attempt a fast NAS-side search via SSH exec_command.
            Raises RuntimeError if SSH exec does not work on this NAS.
            Returns list of matching paths (may be empty if no files match).
            """
            if not self._check_ssh_exec_works():
                raise RuntimeError("SSH exec_command not supported on this NAS")

            def escape_sh(s):
                return s.replace("'", "'\\''")

            all_paths = []
            chunk_size = 20
            packet_ids_list = list(packet_ids)
            for i in range(0, len(packet_ids_list), chunk_size):
                chunk = packet_ids_list[i:i + chunk_size]
                target_str = " -o ".join(f"-name '*{escape_sh(pid)}*'" for pid in chunk)
                find_cmd = f"find '{escape_sh(root)}' -type f \\( {target_str} \\) 2>/dev/null"
                _, stdout_ch, _ = self.ssh.exec_command(find_cmd, timeout=60)
                stdout_ch.channel.settimeout(60)
                # Read line by line to avoid buffering deadlocks
                for line in stdout_ch:
                    p = line.rstrip("\n")
                    if p:
                        all_paths.append(p)
            return all_paths

        ssh_paths = None
        try:
            ssh_paths = _try_ssh_find()
        except Exception:
            ssh_paths = None

        if ssh_paths is not None:
            # SSH fast path succeeded (and SSH exec is verified working on this NAS)
            for p in ssh_paths:
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("Packet search cancelled.")
                if stop_when_all_found and all(counts[key] >= max_results_per_packet for key in counts):
                    break
                p = normalize_remote_path(p)
                filename = posixpath.basename(p)
                filename_key = filename.casefold()
                for packet_key, packet_id in packet_keys.items():
                    if packet_key in filename_key and counts[packet_key] < max_results_per_packet:
                        counts[packet_key] += 1
                        try:
                            item = self.sftp.stat(p)
                            results.append(
                                PacketSearchResult(
                                    packet_id=packet_id,
                                    packet_name=filename,
                                    found_location=p,
                                    nas_source=self.name,
                                    size=item.st_size,
                                    modified_time=item.st_mtime,
                                    status="Found",
                                    profile=self.profile_name,
                                )
                            )
                        except OSError:
                            pass

            found = {result.packet_id.casefold() for result in results}
            for packet_id in packet_ids:
                if packet_id.casefold() not in found:
                    results.append(
                        PacketSearchResult(
                            packet_id=packet_id,
                            packet_name="",
                            found_location="",
                            nas_source=self.name,
                            size=0,
                            modified_time=0,
                            status="Not found",
                            profile=self.profile_name,
                        )
                    )
            return results

        # SSH exec not available on this NAS — fall back to reliable SFTP recursive walk

        def walk(remote_dir):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("Packet search cancelled.")
            if stop_when_all_found and all(counts[key] >= max_results_per_packet for key in counts):
                return
            try:
                items = self.sftp.listdir_attr(remote_dir)
            except OSError:
                return

            for item in items:
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("Packet search cancelled.")
                if stop_when_all_found and all(counts[key] >= max_results_per_packet for key in counts):
                    return
                remote_path = remote_join(remote_dir, item.filename)
                if is_remote_dir(item):
                    walk(remote_path)
                    continue

                if not is_remote_file(item):
                    continue

                filename_key = item.filename.casefold()
                for packet_key, packet_id in packet_keys.items():
                    if packet_key in filename_key and counts[packet_key] < max_results_per_packet:
                        counts[packet_key] += 1
                        results.append(
                            PacketSearchResult(
                                packet_id=packet_id,
                                packet_name=item.filename,
                                found_location=remote_path,
                                nas_source=self.name,
                                size=item.st_size,
                                modified_time=item.st_mtime,
                                profile=self.profile_name,
                            )
                        )

        walk(root)
        found = {result.packet_id.casefold() for result in results}
        for packet_id in packet_ids:
            if packet_id.casefold() not in found:
                results.append(
                    PacketSearchResult(
                        packet_id=packet_id,
                        packet_name="",
                        found_location="",
                        nas_source=self.name,
                        size=0,
                        modified_time=0,
                        status="Not found",
                        profile=self.profile_name,
                    )
                )

        return results


    def find_dirs_by_names(self, folder_names, root="/", max_depth=8, cancel_event=None):
        root = normalize_remote_path(root)
        targets = {str(name).casefold(): str(name) for name in folder_names if name}
        found = defaultdict(list)
        if not targets:
            return found

        try:
            def escape_sh(s):
                return s.replace("'", "'\\''")

            if not self._check_ssh_exec_works():
                raise RuntimeError("SSH exec not supported")

            all_paths = []
            chunk_size = 20
            targets_list = list(targets.values())
            for i in range(0, len(targets_list), chunk_size):
                chunk = targets_list[i:i + chunk_size]
                target_str = " -o ".join(f"-iname '{escape_sh(name)}'" for name in chunk)
                find_cmd = f"find '{escape_sh(root)}' -maxdepth {max_depth} -type d \\( {target_str} \\) 2>/dev/null"
                _, stdout_ch, _ = self.ssh.exec_command(find_cmd, timeout=60)
                stdout_ch.channel.settimeout(60)
                # Read line by line — do NOT call recv_exit_status before read()
                for line in stdout_ch:
                    p = line.rstrip("\n")
                    if p:
                        all_paths.append(p)

            for p in all_paths:
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("Packet search cancelled.")
                p = normalize_remote_path(p)
                name_key = posixpath.basename(p).casefold()
                if name_key in targets:
                    found[targets[name_key]].append(p)
            if len(found) == len(targets):
                return found
        except Exception:
            pass

        stack = [(root, 0)]
        while stack and len(found) < len(targets):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("Packet search cancelled.")

            remote_dir, depth = stack.pop()
            try:
                items = self.sftp.listdir_attr(remote_dir)
            except OSError:
                continue

            for item in items:
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("Packet search cancelled.")
                if not is_remote_dir(item):
                    continue

                remote_path = remote_join(remote_dir, item.filename)
                name_key = item.filename.casefold()
                if name_key in targets:
                    found[targets[name_key]].append(remote_path)
                    continue
                if depth < max_depth:
                    stack.append((remote_path, depth + 1))

        return found

    def search_packets_by_machine_folders(
        self,
        packet_ids,
        machine_folder_by_packet,
        root="/",
        max_results_per_packet=1,
        cancel_event=None,
    ):
        packet_groups = defaultdict(list)
        for packet_id in packet_ids:
            folder = machine_folder_by_packet.get(packet_id)
            if folder:
                packet_groups[folder].append(packet_id)

        folder_paths = self.find_dirs_by_names(packet_groups.keys(), root=root, cancel_event=cancel_event)

        # Fix: if root itself IS the machine folder (user set search root = machine folder path),
        # find_dirs_by_names won't find it as a subdirectory. Add root as a direct candidate.
        root_basename = posixpath.basename(root.rstrip('/'))
        for folder in list(packet_groups.keys()):
            if folder.casefold() == root_basename.casefold() and not folder_paths.get(folder):
                folder_paths[folder] = [root]

        results = []
        found_keys = set()

        for folder, group_packet_ids in packet_groups.items():
            for folder_path in folder_paths.get(folder, []):
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("Packet search cancelled.")
                folder_results = self.search_packets(
                    group_packet_ids,
                    folder_path,
                    max_results_per_packet=max_results_per_packet,
                    cancel_event=cancel_event,
                    stop_when_all_found=True,
                )
                for result in folder_results:
                    if result.status != "Found":
                        continue
                    results.append(result)
                    found_keys.add(result.packet_id.casefold())
                if all(packet_id.casefold() in found_keys for packet_id in group_packet_ids):
                    break

        for packet_id in packet_ids:
            if packet_id.casefold() in found_keys:
                continue
            results.append(
                PacketSearchResult(
                    packet_id=packet_id,
                    packet_name="",
                    found_location="",
                    nas_source=self.name,
                    size=0,
                    modified_time=0,
                    status="Not found",
                    profile=self.profile_name,
                )
            )

        return results

    def download_file(self, remote_path, local_folder, preserve_structure=False):
        remote_path = normalize_remote_path(remote_path)
        local_folder = Path(local_folder)
        if preserve_structure:
            target = local_folder / remote_path.strip("/")
        else:
            target = local_folder / posixpath.basename(remote_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        with self.sftp.open(remote_path, "rb") as source, target.open("wb") as destination:
            while True:
                chunk = source.read(self.chunk_size)
                if not chunk:
                    break
                destination.write(chunk)

        return target

    def upload_file(self, local_path, remote_folder):
        local_path = Path(local_path)
        remote_folder = normalize_remote_path(remote_folder)
        self.mkdir_p(remote_folder)
        remote_path = remote_join(remote_folder, local_path.name)

        with local_path.open("rb") as source, self.sftp.open(remote_path, "wb") as destination:
            while True:
                chunk = source.read(self.chunk_size)
                if not chunk:
                    break
                destination.write(chunk)

        modified = local_path.stat().st_mtime
        self.sftp.utime(remote_path, (modified, modified))
        return remote_path


def copy_remote_to_remote(source_config, destination_config, source_path, destination_folder, chunk_size_mb=DEFAULT_CHUNK_SIZE_MB, max_retries=3):
    import time
    source_path = normalize_remote_path(source_path)
    destination_folder = normalize_remote_path(destination_folder)
    chunk_size = max(1, int(chunk_size_mb or DEFAULT_CHUNK_SIZE_MB)) * 1024 * 1024

    last_error = None
    for attempt in range(max_retries):
        try:
            with NasClient(source_config, chunk_size_mb) as source, NasClient(destination_config, chunk_size_mb) as destination:
                source.sftp.get_channel().settimeout(60.0)
                destination.sftp.get_channel().settimeout(60.0)

                destination.mkdir_p(destination_folder)
                destination_path = remote_join(destination_folder, posixpath.basename(source_path))
                partial_path = destination_path + ".partial"

                try:
                    destination.sftp.remove(partial_path)
                except FileNotFoundError:
                    pass

                with source.sftp.open(source_path, "rb") as source_file, destination.sftp.open(partial_path, "wb") as destination_file:
                    while True:
                        chunk = source_file.read(chunk_size)
                        if not chunk:
                            break
                        destination_file.write(chunk)

                attrs = source.sftp.stat(source_path)
                destination.sftp.rename(partial_path, destination_path)
                destination.sftp.utime(destination_path, (attrs.st_mtime, attrs.st_mtime))
                return destination_path
        except Exception as error:
            last_error = error
            time.sleep(2)

    raise RuntimeError(f"Failed to copy packet after {max_retries} attempts. Last error: {last_error}")
