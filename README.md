# CLI-based Password Manager

A secure, CLI-based password manager written in Go.  
It allows you to store, retrieve, update, delete, and generate passwords, with all data encrypted using AES-GCM.

## Installation

1. Clone the repository
```
git clone https://github.com/danila0x/password-manager.git
cd password-manager
```
2. Run the program
`go run .`

## Usage

- Add a password – enter service name, password (or press Enter to auto‑generate one), and a category.

- Retrieve a password – enter the service name to see its details (including the plain‑text password).

- Update / Delete – modify or remove existing entries.

- Statistics – view total number of passwords, category distribution, and dates of the oldest and newest entries.

- Duplicate detection – lists passwords that are used for more than one service.
