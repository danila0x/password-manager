package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	CapitalCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Lowercase   = "abcdefghijklmnopqrstuvwxyz"
	Digits      = "0123456789"
	Special     = "!@#$%^&*"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
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
	allCharacters := CapitalCase + Lowercase + Digits + Special
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

func (pm *PasswordManager) SaveToFile() error {
	if !pm.isInitialized {
		return fmt.Errorf("manager is not initialized")
	}
	data, err := json.Marshal(pm.passwords)
	if err != nil {
		return fmt.Errorf("json error")
	}
	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return fmt.Errorf("ReadFull error: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	file, err := os.Create(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	n, err := file.Write(nonce)
	if err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}
	if n != len(nonce) {
		return fmt.Errorf("short write: wrote %d of %d nonce bytes", n, len(nonce))
	}
	n, err = file.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}
	if n != len(ciphertext) {
		return fmt.Errorf("short write: wrote %d of %d ciphertext bytes", n, len(ciphertext))
	}
	return nil
}

func (pm *PasswordManager) LoadFromFile() error {
	if !pm.isInitialized {
		return fmt.Errorf("manager is not initialized")
	}
	file, err := os.Open(pm.filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(file, nonce)
	if err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}
	ciphertext, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read cipher text: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	var passwords map[string]Password
	err = json.Unmarshal(plaintext, &passwords)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	pm.passwords = passwords
	return nil
}

func (pm *PasswordManager) CheckPasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password is too weak")
	}
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, r := range password {
		if strings.ContainsRune(CapitalCase, r) {
			hasUpper = true
		}
		if strings.ContainsRune(Lowercase, r) {
			hasLower = true
		}
		if strings.ContainsRune(Digits, r) {
			hasDigit = true
		}
		if strings.ContainsRune(Special, r) {
			hasSpecial = true
		}
	}
	if hasUpper && hasLower && hasDigit && hasSpecial {
		return nil
	} else {
		return fmt.Errorf("password is too weak")
	}
}

func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	var res []Password
	for _, password := range pm.passwords {
		if strings.EqualFold(password.Category, category) {
			res = append(res, password)
		}
	}
	return res
}

func (pm *PasswordManager) FindDuplicatePasswords() map[string][]string {
	passMap := make(map[string][]string)
	for name, pass := range pm.passwords {
		passMap[pass.Value] = append(passMap[pass.Value], name)
	}
	res := make(map[string][]string)
	for value, names := range passMap {
		if len(names) > 1 {
			res[value] = names
		}
	}
	return res
}

func (pm *PasswordManager) UpdatePassword(name, newValue string) error {
	if !pm.isInitialized {
		return fmt.Errorf("manager is not initialized")
	}
	pass, ok := pm.passwords[name]
	if !ok {
		return fmt.Errorf("password not found")
	}
	err := pm.CheckPasswordStrength(newValue)
	if err != nil {
		return fmt.Errorf("update password error: %w", err)
	}
	newPass := Password{
		Name:         name,
		Value:        newValue,
		Category:     pass.Category,
		CreatedAt:    pass.CreatedAt,
		LastModified: time.Now(),
	}
	pm.passwords[name] = newPass
	return nil
}

func (pm *PasswordManager) DeletePassword(name string) error {
	if !pm.isInitialized {
		return fmt.Errorf("manager is not initialized")
	}
	_, ok := pm.passwords[name]
	if !ok {
		return fmt.Errorf("Deleting a nonexistent password: password not found")
	}
	delete(pm.passwords, name)
	return nil
}

func (pm *PasswordManager) ListCategories() []string {
	categoryMap := make(map[string]bool)
	for _, pass := range pm.passwords {
		categoryMap[pass.Category] = true
	}
	result := make([]string, 0, len(categoryMap))
	for key := range categoryMap {
		result = append(result, key)
	}
	return result
}

func (pm *PasswordManager) GetPasswordStats() map[string]any {
	resMap := make(map[string]any)
	lengthPasswords := len(pm.passwords)
	resMap["total"] = lengthPasswords
	categoryStats := make(map[string]int)
	for _, cat := range pm.ListCategories() {
		categoryStats[cat] = len(pm.GetPasswordsByCategory(cat))
	}
	resMap["categories"] = categoryStats
	var minDatePass time.Time
	var maxDatePass time.Time
	first := true
	for _, pass := range pm.passwords {
		if first {
			minDatePass = pass.CreatedAt
			maxDatePass = pass.CreatedAt
			first = false
		}
		if first == false {
			if pass.CreatedAt.Before(minDatePass) {
				minDatePass = pass.CreatedAt
			}
			if pass.CreatedAt.After(maxDatePass) {
				maxDatePass = pass.CreatedAt
			}
		}
	}
	resMap["oldest"] = minDatePass
	resMap["newest"] = maxDatePass
	return resMap
}

func clearScreen() {
	fmt.Print("\033[2J") // очищает экран
	fmt.Print("\033[H")  // перемещает курсор в начало
}

func showSuccess(message string) {
	successMessage := fmt.Sprintf("%sSucces: %s%s", colorGreen, message, colorReset)
	fmt.Println(successMessage)
}

func showError(message string) {
	errorMessage := fmt.Sprintf("%sError: %s%s", colorRed, message, colorReset)
	fmt.Println(errorMessage)
}

func showInfo(message string) {
	infoMessage := fmt.Sprintf("%sInfo:%s%s", colorYellow, message, colorReset)
	fmt.Println(infoMessage)
}

func waitForEnter() {
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		return
	}
	input = strings.TrimSpace(input)
	fmt.Printf("You entered: %q\n", input)
}

func ReadUserInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input: %w", err)
		return ""
	}
	input = strings.TrimSpace(input)
	return input
}

func ReadPassword() (string, error) {
	res, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("Error reading password: %w", err)
	}
	return string(res), nil
}
