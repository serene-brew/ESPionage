<div align=center>

<img src="https://github.com/user-attachments/assets/56f4e53d-b5c3-4982-818e-432c1a79f673" width=200 height=200>

# ESPionage
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](https://github.com/serene-brew/ESPionage)
[![Platform](https://img.shields.io/badge/platform-ESP32/ESP8266-blue.svg?style=social&logo=github)](https://github.com/serene-brew/ESPionage)
[![stars](https://img.shields.io/github/stars/serene-brew/ESPionage?style=social)](https://github.com/serene-brew/ESPionage/stargazers)
[![forks](https://img.shields.io/github/forks/serene-brew/ESPionage?style=social)](https://github.com/serene-brew/ESPionage/network/members)
[![Issues](https://img.shields.io/github/issues/serene-brew/ESPionage.svg?style=social&logo=github)](https://github.com/serene-brew/ESPionage/issues)
[![Python](https://img.shields.io/badge/Python-3.13-yellow.svg)](https://python.org)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)
</div>

#### *<div align="right"><sub>// Made with ❣️ by Serene-Brew<br>MintRaven & RiserSama</sub></div>*

ESPionage is an advanced firmware analysis toolkit developed for reverse engineers, and embedded developers working with ESP32 and ESP8266 platforms. Whether you're dissecting a firmware binary for vulnerabilities, exploring custom hardware behavior, or simply curious about how your device operates under the hood — ESPionage provides the essential tools in one cohesive package.

---

## Features

- **Binary & ELF Support**  
  Analyze both `.bin` and `.elf` firmware formats with ease.

- **Disassembler**  
  Understand your firmware at the instruction level.

- **Firmware Parser**  
  Read partition tables, headers, and memory maps from ESP firmware.

- **Hex Viewer**  
  Explore raw bytes of firmware with an intuitive hex view.

- **Firmware Extractor**  
  Extract firmware directly from connected ESP32/ESP8266 devices.

- **Firmware Flasher**  
  Flash binaries back into ESP32 or ESP8266 targets safely and quickly.

---

## Installation

```bash
git clone https://github.com/serene-brew/ESPionage.git
cd ESPionage
./install.sh
```


## Uninstallation

```bash
espionage --uninstall
```

## Disclaimer

ESPionage is intended for educational and ethical research purposes only.  
Ensure you have proper authorization before extracting or analyzing firmware from any device.

<p align="center">Copyright &copy; 2025 <a href="https://github.com/serene-brew" target="_blank">Serene Brew</a>
<p align="center"><a href="https://github.com/serene-brew/ESPionage/blob/main/LICENSE"><img src="https://img.shields.io/static/v1.svg?style=for-the-badge&label=License&message=BSD-3CLAUSE&logoColor=d9e0ee&colorA=363a4f&colorB=b7bdf8"/></a></p>
