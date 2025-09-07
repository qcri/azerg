from huggingface_hub import snapshot_download

def main():
    dataset_name = "QCRI/AZERG-Dataset"
    save_dir = "./AZERG-Dataset"

    print(f"Downloading {dataset_name} ...")
    # Download full dataset snapshot
    snapshot_download(
        repo_id=dataset_name,
        repo_type="dataset",
        local_dir=save_dir,
        local_dir_use_symlinks=False  # copy instead of symlinks
    )

    print(f"✅ Dataset downloaded into {save_dir}")

if __name__ == "__main__":
    main()
