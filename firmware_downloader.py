name: Firmware Auto Downloader

on:
  schedule:
    - cron: '0 * * * *' # 每小时运行
  workflow_dispatch:
    inputs:
      force_update:
        description: 'Force update check'
        required: false
        default: false
        type: boolean

jobs:
  download_and_release:
    runs-on: ubuntu-latest
    permissions:
      contents: write

    steps:
      - name: ⬇️ Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: 🐍 Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.x'
      
      - name: ⚙️ Install dependencies
        run: |
          pip install requests anynet beautifulsoup4
          sudo apt-get update
          sudo apt-get install -y aria2

      # === 关键修复：还原密钥文件 (参考代码中缺失的部分) ===
      - name: 🔑 Restore critical keys
        env:
          PROD_KEYS: ${{ secrets.PROD_KEYS }}
          CERT_PEM: ${{ secrets.CERT_PEM }}
          PRODINFO_BIN: ${{ secrets.PRODINFO_BIN }}
        run: |
          echo "$PROD_KEYS" > prod.keys
          echo "$CERT_PEM" > certificat.pem
          echo "$PRODINFO_BIN" | base64 -d > PRODINFO.bin
          
          if [ ! -s prod.keys ] || [ ! -s certificat.pem ]; then
             echo "::error::Secrets (prod.keys or certificat.pem) are missing!"
             exit 1
          fi

      - name: 🛠️ Setup hactool
        run: |
          if [ -f "hactool-linux" ]; then
            cp hactool-linux hactool
            chmod +x hactool
          else
            echo "::warning::hactool-linux not found. Ensure it is in the repo."
          fi
          
      - name: 🔍 Check firmware version
        id: version_check
        env:
          FORCE_UPDATE: ${{ inputs.force_update }}
        run: |
          # 从 RSS 获取最新版本
          LATEST_TITLE=$(curl -s 'https://yls8.mtheall.com/ninupdates/feed.php' | \
                         grep '<title>Switch ' | \
                         grep -v '<title>Switch 2 ' | \
                         head -n 1)

          if [ -z "$LATEST_TITLE" ]; then
            echo "::error::RSS feed returned empty data."
            exit 1 
          fi

          LATEST_VERSION=$(echo "$LATEST_TITLE" | grep -oP 'Switch \K[0-9.]+')
          echo "INFO: Detected latest version: $LATEST_VERSION"

          # 检查 Git Tag 是否已存在
          TAG_EXISTS=$(git ls-remote --tags origin $LATEST_VERSION)

          if [ ! -z "$TAG_EXISTS" ] && [ "$FORCE_UPDATE" != "true" ]; then
            echo "INFO: Tag $LATEST_VERSION already exists. Skipping."
            echo "new_version=false" >> $GITHUB_OUTPUT
          else
            echo "INFO: New version found (or forced). Starting download..."
            echo "new_version=true" >> $GITHUB_OUTPUT
            echo "target_version=$LATEST_VERSION" >> $GITHUB_OUTPUT
          fi
        shell: bash

      - name: 💻 Execute download script
        id: download
        if: steps.version_check.outputs.new_version == 'true'
        # 开启 pipefail 确保 Python 报错能导致步骤失败
        shell: bash
        run: |
          set -o pipefail
          python3 firmware_downloader.py "${{ steps.version_check.outputs.target_version }}" | tee firmware_output.txt
          
          # 从日志中提取文件夹名称，用于后续步骤
          # 脚本输出示例: "Folder: Firmware 19.0.2"
          FIRMWARE_VERSION=$(grep 'Folder: Firmware ' firmware_output.txt | head -n 1 | awk -F'Fimware ' '{print $NF}' | awk '{print $NF}')
          
          # 如果 grep 没找到，使用 target_version
          if [ -z "$FIRMWARE_VERSION" ]; then
            FIRMWARE_VERSION="${{ steps.version_check.outputs.target_version }}"
          fi
          
          echo "firmware_version=$FIRMWARE_VERSION" >> $GITHUB_OUTPUT

      - name: 📦 Create Release
        if: steps.version_check.outputs.new_version == 'true'
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ steps.download.outputs.firmware_version }}
          name: Firmware ${{ steps.download.outputs.firmware_version }}
          body: |
            Automatic download from Nintendo CDN.
            Version: **${{ steps.download.outputs.firmware_version }}**
          files: |
            Firmware ${{ steps.download.outputs.firmware_version }}.zip
          make_latest: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
