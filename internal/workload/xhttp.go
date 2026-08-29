package workload

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

const (
	XHTTPModule         = "xhttp"
	XHTTPSchema         = "bastionctl.workload.xhttp.v1"
	XHTTPRelease        = "v3.7.0"
	XHTTPPublicPort     = 443
	XHTTPChallengePort  = 80
	XHTTPCredentialPath = "/etc/bastionctl/workloads/xhttp-access.txt"
	XHTTPMarkerPath     = "/etc/bastionctl/workloads/xhttp.json"
)

var domainLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// XHTTPConfig is the non-secret desired state shared by the admin wizard and
// the constrained server-side workload runner. Panel credentials are generated
// on the server and never included in this structure or JSON reports.
type XHTTPConfig struct {
	Schema      string `json:"schema"`
	Domain      string `json:"domain"`
	Email       string `json:"email"`
	ServerIP    string `json:"server_ip"`
	PanelPort   int    `json:"panel_port"`
	WebBasePath string `json:"web_base_path"`
	Release     string `json:"release"`
}

type ManualStep struct {
	Title   string
	Details []string
}

func NewXHTTPConfig(domain, email, serverIP string, panelPort int) (XHTTPConfig, error) {
	if panelPort == 0 {
		value, err := randomPort()
		if err != nil {
			return XHTTPConfig{}, err
		}
		panelPort = value
	}
	path, err := randomToken(12)
	if err != nil {
		return XHTTPConfig{}, err
	}
	value := XHTTPConfig{
		Schema: XHTTPSchema, Domain: strings.ToLower(strings.TrimSpace(domain)),
		Email: strings.TrimSpace(email), ServerIP: strings.TrimSpace(serverIP),
		PanelPort: panelPort, WebBasePath: "panel-" + path, Release: XHTTPRelease,
	}
	if err := value.Validate(); err != nil {
		return XHTTPConfig{}, err
	}
	return value, nil
}

func (c XHTTPConfig) Validate() error {
	if c.Schema != XHTTPSchema {
		return fmt.Errorf("неподдерживаемая схема XHTTP %q", c.Schema)
	}
	if c.Release != XHTTPRelease {
		return fmt.Errorf("разрешён только проверенный релиз 3x-ui %s", XHTTPRelease)
	}
	if err := ValidateDomain(c.Domain); err != nil {
		return err
	}
	if err := validateEmail(c.Email); err != nil {
		return err
	}
	ip := net.ParseIP(strings.TrimSpace(c.ServerIP))
	if ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return errors.New("публичный IPv4 сервера указан неверно")
	}
	if c.PanelPort < 1024 || c.PanelPort > 65535 || c.PanelPort == XHTTPPublicPort {
		return errors.New("локальный порт панели должен быть в диапазоне 1024..65535 и не равен 443")
	}
	if len(c.WebBasePath) < 12 || len(c.WebBasePath) > 64 {
		return errors.New("путь панели должен содержать 12–64 символа")
	}
	for _, char := range c.WebBasePath {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return errors.New("путь панели может содержать только a-z, 0-9 и дефис")
		}
	}
	return nil
}

func ValidateDomain(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 4 || len(value) > 253 || strings.HasSuffix(value, ".") || net.ParseIP(value) != nil {
		return errors.New("домен должен быть полным DNS-именем без точки в конце")
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return errors.New("домен должен содержать как минимум две DNS-метки")
	}
	for _, label := range labels {
		if !domainLabelPattern.MatchString(label) {
			return fmt.Errorf("недопустимая DNS-метка %q", label)
		}
	}
	if len(labels[len(labels)-1]) < 2 {
		return errors.New("доменная зона слишком короткая")
	}
	return nil
}

func validateEmail(value string) error {
	if len(value) < 3 || len(value) > 254 || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("email для Let's Encrypt указан неверно")
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || strings.Contains(value, " ") {
		return errors.New("email для Let's Encrypt указан неверно")
	}
	return nil
}

func IsXHTTPAction(action string) bool {
	return action == "plan" || action == "apply" || action == "verify"
}

func XHTTPReportAction(action string) string {
	return "workload-xhttp-" + action
}

func (c XHTTPConfig) CertificatePath() string {
	return "/etc/letsencrypt/live/" + c.Domain + "/fullchain.pem"
}

func (c XHTTPConfig) PrivateKeyPath() string {
	return "/etc/letsencrypt/live/" + c.Domain + "/privkey.pem"
}

func (c XHTTPConfig) LocalPanelURL(localPort int) string {
	return "http://127.0.0.1:" + strconv.Itoa(localPort) + "/" + c.WebBasePath + "/"
}

func XHTTPPanelDestination(c XHTTPConfig) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(c.PanelPort))
}

func ManualGuide(c XHTTPConfig, target, identity string, sshPort, localPort int) []ManualStep {
	identityArgument := ""
	if strings.TrimSpace(identity) != "" {
		identityArgument = " -i " + quoteCommandArgument(identity, runtime.GOOS)
	}
	connection := "ssh -p " + strconv.Itoa(sshPort) + identityArgument + " " + quoteCommandArgument(target, runtime.GOOS)
	tunnel := "ssh -N -L 127.0.0.1:" + strconv.Itoa(localPort) + ":127.0.0.1:" + strconv.Itoa(c.PanelPort) + " -p " + strconv.Itoa(sshPort) + identityArgument + " " + quoteCommandArgument(target, runtime.GOOS)
	return []ManualStep{
		{
			Title: "До установки: домен и внешняя сеть",
			Details: []string{
				"Купите или используйте собственный домен и создайте A-запись " + c.Domain + " → " + c.ServerIP + ".",
				"Если у сервера нет рабочего IPv6, не создавайте AAAA-запись. Неверная AAAA-запись ломает выпуск сертификата.",
				"В панели VPS/провайдера разрешите входящий TCP 80 и 443. Порт панели " + strconv.Itoa(c.PanelPort) + " наружу не открывайте.",
				"Дождитесь обновления DNS и проверьте, что домен возвращает IP сервера.",
			},
		},
		{
			Title: "Первый вход в локальную панель 3x-ui",
			Details: []string{
				"Подключитесь к серверу: " + connection,
				"Посмотрите одноразовые данные: sudo cat " + XHTTPCredentialPath,
				"В отдельном терминале откройте SSH-туннель: " + tunnel,
				"Откройте " + c.LocalPanelURL(localPort) + ", войдите, сохраните пароль в менеджере паролей и включите 2FA.",
				"После успешного входа удалите временный файл: sudo rm -- " + XHTTPCredentialPath,
			},
		},
		{
			Title: "Создание VLESS + TLS + XHTTP",
			Details: []string{
				"В 3x-ui откройте «Подключения» и создайте inbound: протокол VLESS, порт 443, transport XHTTP, security TLS, decryption none.",
				"Укажите домен/SNI " + c.Domain + ", сертификат " + c.CertificatePath() + " и ключ " + c.PrivateKeyPath() + ".",
				"Создайте клиента с новым UUID. Начните с режима XHTTP auto; затем при необходимости сравните stream-up, stream-one и packet-up на своей сети.",
				"После изменения XHTTP/ECH-параметров нажмите «Get New ECH Cert», если этот пункт показан текущей версией панели.",
				"Скопируйте ссылку или QR-код в клиент на Xray Core. После проверки вернитесь в bastionctl и запустите «Проверить». ",
			},
		},
	}
}

func randomPort() (int, error) {
	value := make([]byte, 2)
	if _, err := rand.Read(value); err != nil {
		return 0, err
	}
	raw := int(value[0])<<8 | int(value[1])
	port := 20000 + raw%40000
	if port == XHTTPPublicPort || port == XHTTPChallengePort {
		port++
	}
	return port, nil
}

func randomToken(bytesCount int) (string, error) {
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func quoteCommandArgument(value, goos string) string {
	if value != "" && strings.IndexFunc(value, func(char rune) bool {
		return !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("@%_+=:,./-", char))
	}) == -1 {
		return value
	}
	if goos == "windows" {
		return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
	}
	return `'` + strings.ReplaceAll(value, `'`, `'"'"'`) + `'`
}
