import os
import shutil
import hashlib
import requests
import stat
from git import Repo
from git.exc import GitCommandError, InvalidGitRepositoryError, NoSuchPathError

def handle_remove_readonly(func, path, exc_info):
    """Handle permissions errors by changing file mode and retrying."""
    os.chmod(path, stat.S_IWRITE)
    func(path)

def check_git_repo(directory):
    """Check if a directory is a valid Git repo."""
    try:
        return Repo(directory)
    except (InvalidGitRepositoryError, NoSuchPathError):
        return None

def update_git_repo(repo):
    """Update the local Git repository."""
    try:
        current_commit = repo.head.commit.hexsha
        print("Pulling latest changes...")
        repo.remotes.origin.pull()
        new_commit = repo.head.commit.hexsha
        
        if current_commit == new_commit:
            print("Repo is up to date. No changes were made.")
        else:
            print("Repo updated.")
    except GitCommandError as e:
        print(f"Failed to update repo: {e}")

def clone_git_repo(directory, repo_url, subdir_name):
    """Clone a Git repo into a subdirectory."""
    subdir_path = os.path.join(directory, subdir_name)
    
    if os.path.exists(subdir_path):
        print(f"{subdir_path} already exists. Removing to avoid conflicts.")
        try:
            shutil.rmtree(subdir_path, onerror=handle_remove_readonly)
        except Exception as e:
            print(f"Failed to remove {subdir_path}: {e}")
            return None

    try:
        print(f"Cloning repo into: {subdir_path}")
        repo = Repo.clone_from(repo_url, subdir_path)
        print("Cloning complete.")
        return repo
    except GitCommandError as e:
        print(f"Failed to clone repo: {e}")
        return None

def download_file(url, local_path):
    """Download a file from a URL to a local path."""
    try:
        print(f"Downloading file from {url}")
        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(local_path, 'wb') as f:
            f.write(response.content)
        print(f"File downloaded successfully: {local_path}")
    except requests.RequestException as e:
        print(f"Failed to download file: {e}")

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    hash_func = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def is_file_outdated(local_file, remote_url):
    """Check if the local file is outdated by comparing its hash with the remote file."""
    if not os.path.exists(local_file):
        return True

    local_hash = calculate_file_hash(local_file)
    print(f"Checking for changes: {remote_url}")
    
    response = requests.get(remote_url)
    response.raise_for_status()
    remote_hash = hashlib.sha256(response.content).hexdigest()

    return local_hash != remote_hash

def handle_repository(repo_url, subdir_name, script_directory):
    """Handle checking, updating, or cloning a Git repository."""
    subdir_path = os.path.join(script_directory, subdir_name)
    repo = check_git_repo(subdir_path)

    if repo:
        print(f"Local {subdir_name} repo found.")
        update_git_repo(repo)
    else:
        print(f"Cloning {subdir_name} repo...")
        clone_git_repo(script_directory, repo_url, subdir_name)

def handle_file_download(file_url, local_file_path):
    """Handle checking and downloading a file if outdated."""
    if is_file_outdated(local_file_path, file_url):
        print(f"{os.path.basename(local_file_path)} is outdated or missing. Downloading latest...")
        download_file(file_url, local_file_path)
    else:
        print(f"{os.path.basename(local_file_path)} is up to date.")

def main():
    script_directory = os.path.dirname(os.path.abspath(__file__))

    # Handle VanillaWindowsReference repository
    vwr_repo_url = "https://github.com/AndrewRathbun/VanillaWindowsReference.git"
    handle_repository(vwr_repo_url, "VanillaWindowsReference", script_directory)

    # Handle LOLDrivers repository
    loldrivers_repo_url = "https://github.com/magicsword-io/LOLDrivers.git"
    handle_repository(loldrivers_repo_url, "LOLDrivers", script_directory)

    # Handle lolbas.csv file
    lolbas_csv_url = "https://lolbas-project.github.io/api/lolbas.csv"
    local_lolbas_csv = os.path.join(script_directory, "lolbas.csv")
    handle_file_download(lolbas_csv_url, local_lolbas_csv)

if __name__ == "__main__":
    main()
