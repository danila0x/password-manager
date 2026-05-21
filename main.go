package main

import (
	"fmt"
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
	fmt.Println(pm)
	err := pm.SetMasterPassword("asass")
	if err != nil {
		fmt.Printf("Weak master password: %v", err)
	} else {
		fmt.Printf("Strong master password:: %v\n", pm.masterKey)
		fmt.Printf("Manager initialized: %v\n", pm.isInitialized)
		fmt.Printf("Master key length: %v\n", len(pm.masterKey))

	}
}
