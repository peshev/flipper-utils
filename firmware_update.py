import datetime
import hashlib
import json
import re
import shutil
import subprocess
import time
from urllib.parse import urljoin, urlparse

import requests
import lxml.html
import zipfile
import io
import os
import tqdm


class CustomZipFile(zipfile.ZipFile):
    def _get_traget_file_path(self, targetpath, filename):
        """
        Copied from zipfile.ZipFile._extract_member()
        """
        # build the destination pathname, replacing
        # forward slashes to platform specific separators.
        arcname = filename.replace('/', os.path.sep)

        if os.path.altsep:
            arcname = arcname.replace(os.path.altsep, os.path.sep)
        # interpret absolute pathname as relative, remove drive letter or
        # UNC path, redundant separators, "." and ".." components.
        arcname = os.path.splitdrive(arcname)[1]
        invalid_path_parts = ('', os.path.curdir, os.path.pardir)
        arcname = os.path.sep.join(x for x in arcname.split(os.path.sep)
                                   if x not in invalid_path_parts)
        if os.path.sep == '\\':
            # filter illegal characters on Windows
            arcname = self._sanitize_windows_name(arcname, os.path.sep)

        targetpath = os.path.join(targetpath, arcname)
        return os.path.normpath(targetpath)

    def _extract_member(self, member, targetpath, pwd):
        """
        Copied from zipfile.ZipFile._extract_member()
        """

        # Create all upper directories if necessary.
        upperdirs = os.path.dirname(targetpath)
        if upperdirs and not os.path.exists(upperdirs):
            os.makedirs(upperdirs)

        if member.is_dir():
            if not os.path.isdir(targetpath):
                os.mkdir(targetpath)
            return targetpath

        with self.open(member, pwd=pwd) as source, \
                open(targetpath, "wb") as target:
            shutil.copyfileobj(source, target)

        return targetpath

    @staticmethod
    def find_leading_dirs(member_filenames):
        leading_dirs = []
        while True:
            current_dirs = set()
            new_member_filenames = []
            for f in member_filenames:
                if "/" in f:
                    d, rest = f.split("/", maxsplit=1)
                    current_dirs.add(d)
                    if len(current_dirs) > 1:
                        return "/".join(leading_dirs)
                    if rest:
                        new_member_filenames.append(rest)
            if current_dirs:
                assert len(current_dirs) == 1
                leading_dirs.append(next(iter(current_dirs)))
            else:
                return "/".join(leading_dirs)
            member_filenames = new_member_filenames

    def extractall(self, path=None, members=None, pwd=None, strip_leading_dirs=False):
        """Extract all members from the archive to the current working
           directory. `path' specifies a different directory to extract to.
           `members' is optional and must be a subset of the list returned
           by namelist().

           Copied from zipfile.ZipFile.extractall()
        """
        if members is None:
            members = self.infolist()

        leading_dirs = None
        if strip_leading_dirs:
            leading_dirs = self.find_leading_dirs([m.filename for m in members])

        if path is None:
            path = os.getcwd()
        else:
            path = os.fspath(path)

        for zipinfo in members:
            targetfile = zipinfo.filename
            if leading_dirs:
                assert targetfile.startswith(leading_dirs)
                targetfile = targetfile[len(leading_dirs):].lstrip("/")
            targetpath = self._get_traget_file_path(path, targetfile)
            self._extract_member(zipinfo, targetpath, pwd)

            date_time = time.mktime(zipinfo.date_time + (0, 0, -1))
            os.utime(targetpath, (date_time, date_time))
            yield targetpath


def get_dir_metadata(dir_path):
    return {
        "type": "directory",
        "mtime": os.path.getmtime(dir_path)
    }


def get_file_metadata(file_path, bufsize=4 * 1024):
    md5 = hashlib.md5()
    with open(file_path, "rb") as fp:
        while True:
            b = fp.read(bufsize)
            if not len(b):
                break
            md5.update(b)
    return {
        "type": "file",
        "mtime": os.path.getmtime(file_path),
        "size": os.path.getsize(file_path),
        "md5": md5.hexdigest()
    }


def get_recursive_metadata(dirname, base_dirname):
    file_metadata = {}
    for path, dirs, files in os.walk(os.path.join(base_dirname, dirname)):
        assert path.startswith(base_dirname)
        relpath = path[len(base_dirname):].lstrip("/")
        for entries, fn in [(dirs, get_dir_metadata), (files, get_file_metadata)]:
            for i in entries:
                file_metadata[os.path.join(relpath, i)] = fn(os.path.join(path, i))
    return file_metadata


def get_metadata_for_dirs(dirs, base):
    return {k: v for d in dirs for k, v in get_recursive_metadata(d, base).items()}


def get_mounts():
    with open("/etc/mtab", "r") as fp:
        mounts = {}
        for l in fp.readlines():
            l = l.rstrip("\n")
            if l:
                dev, mountpount, _ = l.split(maxsplit=2)
                mounts[dev] = mountpount.replace("\\040", " ")
    return mounts


def mount_sdcard(sdcard_fslabel):
    print(f"Identifying block device for '{sdcard_fslabel}' ... ", end="", flush=True)
    try:
        sdcard_partition_dev = subprocess.check_output(["blkid", "--label", sdcard_fslabel]).decode().strip()
    except subprocess.CalledProcessError:
        print(f"ERROR: unable to identfy block device with filesystem label '{sdcard_fslabel}'")
        return None, None
    print(sdcard_partition_dev)

    mounts = get_mounts()
    if sdcard_partition_dev not in mounts:
        print(f"Mounting {sdcard_partition_dev} ... ", end="", flush=True)
        subprocess.check_output(["udisksctl", "mount", "-b", sdcard_partition_dev])
        print("done.")

        mounts = get_mounts()
    assert sdcard_partition_dev in mounts, f"ERROR: Could not find {sdcard_partition_dev} in /etc/mtab"
    mountpoint = mounts[sdcard_partition_dev]
    print(f"{sdcard_partition_dev} mounted on {mountpoint}")
    return mountpoint, sdcard_partition_dev


def download_firmware(sdcard_base):
    update_dir = os.path.join(sdcard_base, "update")
    os.makedirs(update_dir, exist_ok=True)

    print("Looking for latest RogueMaster firmware release ...  ", end="", flush=True)
    roguemaster_latest_release = requests.get(
        "https://api.github.com/repos/RogueMaster/flipperzero-firmware-wPlugins/releases/latest"
    ).json()
    print(roguemaster_latest_release["name"])

    roguemaster_download_url = roguemaster_latest_release["assets"][0]["browser_download_url"]

    print(f"Downloading RogueMaster release from {roguemaster_download_url} ... ", end="", flush=True)
    roguemaster_release_bytes = requests.get(roguemaster_download_url).content
    print("done.")

    with CustomZipFile(io.BytesIO(roguemaster_release_bytes)) as z:
        for _ in tqdm.tqdm(z.extractall(update_dir, strip_leading_dirs=True),
                           desc="Extracting RogueMaster release",
                           total=len(z.infolist())):
            pass


tail_regex = re.compile(r'\s*files? to (?:the )?SD/(\S+)')


def parse_file_list_links(url="https://flipper.pingywon.com/"):
    print(f"Getting asset file directories from {url} ... ", end="", flush=True)
    links = lxml.html.fromstring(
        requests.get(url).content
    ).xpath("//h2[contains(text(),'MISC NOTES')]/following-sibling::ul/li/a")
    print("done.")
    assert links, f"ERROR: No asset file directories parsed at {url}. Maybe something changed on the page?"
    for i in tqdm.tqdm(links, desc="Parsing asset file directory listings"):
        tail = i.tail.strip()
        match = tail_regex.search(tail)
        if match:
            yield i.attrib["href"], match.group(1)
        else:
            print(f"'{tail}' doesn't match '{tail_regex.pattern}'")


def parse_file_list(url):
    def parse_tr(tr):
        assert len(tr) == 3
        a = tr[0][0]
        assert a.tag == 'a'
        href = a.attrib["href"]
        if href != "../":
            return {
                "url": urljoin(url, href),
                "size": tr[1].text.strip(),
                "date": datetime.datetime.strptime(tr[2].text, "%Y-%b-%d %H:%M"),
            }

    for tr in lxml.html.fromstring(requests.get(url).content).xpath("//table[@id='list']/tbody/tr"):
        file_info = parse_tr(tr)
        if file_info:
            yield file_info


def parse_all_file_lists():
    return [
        {**file_info, "path": path}
        for url, path in
        parse_file_list_links()
        for file_info in
        parse_file_list(url)
    ]


def download_files(file_infos, basedir, bufsize=4 * 1024):
    for f in tqdm.tqdm(file_infos, desc="Downloading asset files"):
        resp = requests.get(f["url"], stream=True)
        dir_path = os.path.join(basedir, f["path"])
        os.makedirs(dir_path, exist_ok=True)
        file_path = os.path.join(dir_path, urlparse(f["url"]).path.split("/")[-1])
        with open(file_path, "wb") as fp:
            for chunk in resp.iter_content(bufsize):
                fp.write(chunk)
        date_time = time.mktime(f["date"].timetuple())
        os.utime(file_path, (date_time, date_time))


def compare_file_metadata(old, new):
    print("Comparing previous and new file metadata ... ", end="", flush=True)
    old_filenames = set(old)
    new_filenames = set(new)
    result = {}
    result.update({k: {**old[k], "state": "deleted"} for k in old_filenames - new_filenames})
    result.update({k: {**new[k], "state": "new"} for k in new_filenames - old_filenames})
    for f in old_filenames & new_filenames:
        new_fileinfo = new[f]
        old_fileinfo = old[f]
        assert new_fileinfo["type"] == old_fileinfo["type"]  # we currently don't support type change
        changed = {}
        for k in ["mtime", "size", "md5"]:
            if new_fileinfo[k] != old_fileinfo[k]:
                changed[k] = {"old": old_fileinfo[k], "new": new_fileinfo[k]}
        if changed:
            result[f] = {**changed, "state": "modified"}
    print("done.")
    return result


def dump_file_metadata_diff(diff):
    filename = f"flipper-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
    print(f"Dumping file metadata diff in {filename} ... ", end="", flush=True)
    with open(filename, "w") as fp:
        json.dump(diff, fp)
    print("done.")


if __name__ == '__main__':
    sdcard_base, sdcard_partition_dev = mount_sdcard("Flipper SD")
    if not sdcard_base:
        exit(1)
    file_infos = parse_all_file_lists()
    dirs = {f["path"] for f in file_infos} | {'update'}
    old_files = get_metadata_for_dirs(dirs, sdcard_base)
    download_firmware(sdcard_base)
    download_files(file_infos, sdcard_base)
    new_files = get_metadata_for_dirs(dirs, sdcard_base)
    diff = compare_file_metadata(old_files, new_files)
    dump_file_metadata_diff(diff)

    firmware_changed = False
    for k, v in diff.items():
        dirname, _ = k.split("/", maxsplit=1)
        if dirname == "update" and (v["state"] == "new" or (v["state"] == "modified" and "md5" in v)):
            firmware_changed = True
            break
    if firmware_changed:
        print(f"Un-mounting {sdcard_partition_dev} ... ", end="", flush=True)
        subprocess.check_output(["udisksctl", "unmount", "-b", sdcard_partition_dev])
        print("done.")
        print("Remove SD card from computer card reader, "
              "insert SD card in Flipper Zero, "
              "run update in Flipper Zero, "
              "umount SD card in Flipper Zero, "
              "remove SD card from Flipper Zero, "
              "insert SD card in computer card reader, "
              "then press Enter")
        input()
        sdcard_base, sdcard_partition_dev = mount_sdcard("Flipper SD")

    settings_user_filename = "subghz/assets/setting_user"
    print(f"Replacing Add_standard_frequencies: false with true in {settings_user_filename} ... ", end="", flush=True)
    subghz_setting_user_path = os.path.join(sdcard_base, settings_user_filename)
    with open(subghz_setting_user_path, "r") as fp:
        subghz_setting_user = fp.read()
    subghz_setting_user_new = subghz_setting_user.replace("Add_standard_frequencies: false",
                                                          "Add_standard_frequencies: true")
    with open(subghz_setting_user_path, "w") as fp:
        fp.write(subghz_setting_user_new)
    print("done.")

    print(f"Un-mounting {sdcard_partition_dev} ... ", end="", flush=True)
    subprocess.check_output(["udisksctl", "unmount", "-b", sdcard_partition_dev])
    print("done.")

    print("ALL DONE.")
