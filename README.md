# Automated Bug Bounty Tool

![Made in India](https://img.shields.io/badge/Made%20in-India-orange?style=for-the-badge\&logo=india\&logoColor=white)
![Made in Bash](https://img.shields.io/badge/Made%20in-Bash-blue?style=for-the-badge\&logo=gnu-bash\&logoColor=white)

## Subdomains Gathering Using Tools

This project uses multiple tools (Amass, Subfinder, Assetfinder, Findomain, Crt, WayBackURL) to discover as many subdomains as possible.

---

## Install `curl` (so you can use the one-liner installer)

Run this to install `curl` on Debian/Ubuntu systems. The command is in a fenced code block so GitHub will show a copy button.

```bash
sudo apt update && sudo apt install curl -y
```

---

## Install (Recommended For Fresh Install)

```bash
curl -sL https://raw.githubusercontent.com/ghost11411/scout/main/configure | bash
```

---

## Install Updates (Recommended For Updating)

Use this to only pull the latest changes without removing local files.

```bash
curl -sL https://raw.githubusercontent.com/ghost11411/scout/main/configure | bash -s -- --update
```

---

## Install Forced (If Nothing Else Works)

```bash
curl -sL https://raw.githubusercontent.com/ghost11411/scout/main/configure | bash -s -- --force
```

---

> **Warning:** This project is heavily under development. Use the `--force` option with care as it will remove the install directory before re-cloning.
