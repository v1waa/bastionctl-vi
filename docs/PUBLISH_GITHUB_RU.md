# Как опубликовать Secure Linux Wizard на GitHub

Ниже два безопасных варианта: через веб-интерфейс или через Git. Не добавляйте в репозиторий приватные SSH-ключи, `.env`, реальные токены, серверные логи и каталоги `/root/security-*`.

## Вариант 1: через сайт GitHub

1. Войдите на GitHub и нажмите **New repository**.
2. Укажите имя `secure-linux-wizard`, описание и видимость `Public` или `Private`.
3. Не добавляйте README, `.gitignore` и лицензию: они уже есть в архиве.
4. Создайте репозиторий.
5. Распакуйте готовый GitHub-архив на компьютере.
6. На странице пустого репозитория выберите **uploading an existing file**.
7. Перетащите содержимое верхней папки, включая скрытые `.github`, `.gitattributes`, `.gitignore` и `.editorconfig`.
8. Commit message: `Initial release v2026.08.10-2`.
9. Откройте вкладку **Actions** и дождитесь зелёного workflow `CI`.
10. В **Settings → Security → Advanced Security** включите **Private vulnerability reporting** (в некоторых интерфейсах раздел ещё называется **Code security and analysis**).
11. Создайте Release с тегом `v2026.08.10-2` и приложите ZIP и внешний файл `.sha256`.

Веб-загрузка иногда не сохраняет пустые каталоги, но в этом проекте пустых обязательных каталогов нет. Проверьте, что `.github/workflows/ci.yml` появился в репозитории.

## Вариант 2: через PowerShell и Git

После создания пустого репозитория распакуйте архив и выполните:

```powershell
cd "$env:USERPROFILE\Downloads\secure-linux-wizard"
git init
git branch -M main
git add --all
git status
git commit -m "Initial release v2026.08.10-2"
git remote add origin https://github.com/YOUR_USERNAME/secure-linux-wizard.git
git push -u origin main
```

Для входа GitHub не принимает пароль аккаунта в Git. Используйте браузерную авторизацию Git Credential Manager, GitHub CLI (`gh auth login`) или Personal Access Token с минимально необходимыми правами. Никогда не вставляйте токен в URL и не сохраняйте его в репозитории.

Создание тега:

```powershell
git tag -a v2026.08.10-2 -m "Secure Linux Wizard v2026.08.10-2"
git push origin v2026.08.10-2
```

Затем откройте **Releases → Draft a new release**, выберите тег и прикрепите релизный ZIP и `.sha256`.

## Проверка перед публикацией

```powershell
Get-FileHash .\secure-linux-wizard-v2026.08.10-2-github.zip -Algorithm SHA256
Get-Content .\secure-linux-wizard-v2026.08.10-2-github.zip.sha256
```

В Linux/macOS:

```bash
sha256sum -c secure-linux-wizard-v2026.08.10-2-github.zip.sha256
```

После push убедитесь, что:

- Actions `bash` и `powershell` зелёные;
- README отображается на русском и английском;
- вкладка Security ссылается на `SECURITY.md`;
- в репозитории нет `.env`, приватных ключей, логов и резервных архивов;
- Release содержит именно проверенный архив.
