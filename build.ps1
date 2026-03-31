$ErrorActionPreference = "Stop"

# 프로젝트 기본 정보
$APP_NAME    = "detectbot"
$MAIN_PKG    = "./cmd/detectbot"
$DIST_DIR    = "dist"

# 버전 정보
$VERSION     = "1.1.3"
$COMMIT      = (git rev-parse --short HEAD) 2>$null
if (-not $COMMIT) { $COMMIT = "unknown" }

$BUILD_TIME  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$VERSION_SUFFIX = $VERSION.Replace(".", "_")

# ldflags
$LDFLAGS = "-s -w -X main.Version=$VERSION -X main.Commit=$COMMIT -X main.BuildTime=$BUILD_TIME"

# dist 초기화
if (Test-Path $DIST_DIR) {
    Remove-Item -Recurse -Force $DIST_DIR
}
New-Item -ItemType Directory -Path $DIST_DIR | Out-Null

Write-Host "==> go mod tidy"
go mod tidy

# 공통 빌드 함수
function Build-Target {
    param (
        [string]$GOOS,
        [string]$GOARCH,
        [string]$EXT = ""
    )

    $outputName = "${APP_NAME}_${GOOS}_${GOARCH}_v${VERSION_SUFFIX}${EXT}"
    $outputPath = Join-Path $DIST_DIR $outputName

    Write-Host "==> Building $outputName"

    $env:GOOS = $GOOS
    $env:GOARCH = $GOARCH
    $env:CGO_ENABLED = "0"

    go build -trimpath -ldflags $LDFLAGS -o $outputPath $MAIN_PKG

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed: $outputName"
    }
}

# Windows
Build-Target -GOOS "windows" -GOARCH "amd64" -EXT ".exe"

# Linux
Build-Target -GOOS "linux" -GOARCH "amd64"

# macOS Intel
Build-Target -GOOS "darwin" -GOARCH "amd64"

# macOS Apple Silicon
Build-Target -GOOS "darwin" -GOARCH "arm64"

Write-Host ""
Write-Host "빌드 완료:"
Get-ChildItem $DIST_DIR
