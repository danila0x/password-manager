package main

import (
	"crypto/rand"
	"fmt"
)

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"`
	masterKey     []byte              `json:"-"`
	filePath      string              `json:"-"`
	isInitialized bool                `json:"-"`
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords:     make(map[string]Password),
		masterKey:     nil,
		filePath:      filePath,
		isInitialized: false,
	}
}

func (pm *PasswordManager) String() string {
	return fmt.Sprintf("Initialized: %v\nFile path: %s\nPasswords count: %d", pm.isInitialized, pm.filePath, len(pm.passwords))
}

func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	if len(masterPassword) < 8 {
		return fmt.Errorf("password is too weak")
	}
	key := make([]byte, 32)
	copy(key, []byte(masterPassword))
	pm.masterKey = key
	pm.isInitialized = true
	return nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if pm.isInitialized == false {
		return fmt.Errorf("password manager not initialized")
	}
	_, ok := pm.passwords[name]
	if ok {
		return fmt.Errorf("password already exists")
	}
	pass := NewPassword(name, value, category)
	pm.passwords[name] = pass
	return nil
}

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, fmt.Errorf("password manager not initialized")
	}
	pass, ok := pm.passwords[name]
	if !ok {
		return Password{}, fmt.Errorf("password not found")
	} else {
		return pass, nil
	}
}

func (pm *PasswordManager) ListPasswords() []Password {
	passwordList := make([]Password, 0, len(pm.passwords))
	for _, value := range pm.passwords {
		passwordList = append(passwordList, value)
	}
	return passwordList
}

func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "", fmt.Errorf("Error for short password: password is too weak")
	}
	capitalCase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	special := "!@#$%^&*"
	allCharacters := capitalCase + lowercase + digits + special
	key := make([]byte, length)
	n, err := rand.Read(key)
	if err != nil || n != length {
		return "", fmt.Errorf("Error for short password: password is too weak")
	}
	res := make([]byte, 0, length)
	for _, b := range key {
		index := int(b) % len(allCharacters)
		res = append(res, allCharacters[index])
	}
	return string(res), nil
}
