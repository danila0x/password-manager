package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"
)

type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
}

func NewPassword(name, value, category string) Password {
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}

func main() {
	pm := NewPasswordManager("password.dat")

	fmt.Println("=== Password Manager Initialization ===")
	fmt.Print("Enter master password: ")
	password, err := readPassword()
	if err != nil {
		log.Fatal(err)
	}
	err = pm.SetMasterPassword(password)
	if err != nil {
		log.Fatal(err)
	}
	showSuccess("Password manager initialized successfully")
	waitForEnter()

	err = pm.LoadFromFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("No existing data file found. Starting fresh.")
		} else {
			fmt.Printf("Warning: failed to load data: %v\n", err)
		}
	}

	for {
		ShowMainMenu()
		var choice int
		fmt.Print("Enter your choice: ")
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			HandlePasswordGeneration(pm)
		case 2:
			HandlePasswordAdd(pm)
		case 3:
			HandlePasswordSearch(pm)
		case 4:
			pm.ListPasswords()
		case 5:
			HandlePasswordUpdate(pm)
		case 6:
			HandleDeletePassword(pm)
		case 7:
			pm.ListCategories()
		case 8:
			HandleShowStats(pm)
		case 9:
			pm.FindDuplicatePasswords()
		case 0:
			HandleExitAndSave(pm)
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
		fmt.Println()
	}
}
