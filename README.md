<p align="center">
    <picture>
        <img src="img/banner.jpg" width=1200px>
    </picture>
</p>

Doom is a Python tool developed to be used in Active Directory environments with Active Directory Certificate Services (ADCS) present. It identifies the ADCS server and enumerates all the templates and their properties, which can be useful to help identify security risks in the certificate templates.

<br>

## Documentation
Documentation is avaible in the Wiki page: [https://github.com/000pp/doom/wiki](https://github.com/000pp/doom/wiki)

<br>

## Installation
We recommend using [pipx](https://github.com/pypa/pipx) to install the project, so you can run it from anywhere and make things easier.

### Linux
```
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/000pp/doom
```

### MacOS
```
brew install pipx
pipx ensurepath
pipx install git+https://github.com/000pp/doom
```

### Local
```
git clone https://github.com/000pp/doom.git
pipx install .
```

### Updating
```
pipx reinstall doom
```

## Why?
Doom was created to help security analysts identify vulnerabilities in certificate templates in an Active Directory environment. Recently, I've seen some posts and talks about false positives in some tools, so why not look at the template manually? Of course, I don't have any problem with these tools or their results; this project is not a war against them or a form of depreciation. It's simply a new way to look at certificate templates.

## To-Do
- [ ] Improve TUI
- [ ] Retrieve more properies from the certificate templates
- [ ] Copy more Certipy code

<br>

## Credits
This tool is totally based on [Certipy's project](https://github.com/ly4k/Certipy). A big shout-out to ly4k and all the maintainers!
