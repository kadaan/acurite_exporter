#!/usr/bin/env bash

# Copyright © 2018 Joel Baranick <jbaranick@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


BUILD_DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"
BINARY_DIR="$BUILD_DIR/.bin"
VERSION=$(cat $BUILD_DIR/.version)

function verbose() { echo -e "$*"; }
function error() { echo -e "ERROR: $*" 1>&2; }
function fatal() { echo -e "ERROR: $*" 1>&2; exit 1; }
function pushd () { command pushd "$@" > /dev/null; }
function popd () { command popd > /dev/null; }

function trap_add() {
  localtrap_add_cmd=$1; shift || fatal "${FUNCNAME} usage error"
  for trap_add_name in "$@"; do
    trap -- "$(
      extract_trap_cmd() { printf '%s\n' "$3"; }
      eval "extract_trap_cmd $(trap -p "${trap_add_name}")"
      printf '%s\n' "${trap_add_cmd}"
    )" "${trap_add_name}" || fatal "unable to add to trap ${trap_add_name}"
  done
}
declare -f -t trap_add

function get_platform() {
  local unameOut="$(uname -s)"
  case "${unameOut}" in
    Linux*)
      echo "linux"
    ;;
    Darwin*)
      echo "darwin"
    ;;
    *)
      echo "Unsupported machine type :${unameOut}"
      exit 1
    ;;
  esac
}

PLATFORM="$(get_platform)"
GLIDE="${BINARY_DIR}/glide"
GLIDE_URL="https://github.com/Masterminds/glide/releases/download/v0.13.1/glide-v0.13.1-$PLATFORM-amd64.tar.gz"
GOX="gox"
GOMETALINTER="${BINARY_DIR}/gometalinter"
GOMETALINTER_URL="https://github.com/alecthomas/gometalinter/releases/download/v2.0.4/gometalinter-2.0.4-$PLATFORM-amd64.tar.gz"
UPX="${BINARY_DIR}/upx"

function download_glide() {
  if [[ ! -f "$GLIDE" ]]; then
    verbose "   --> $GLIDE"
    local tmpdir=`mktemp -d`
    trap_add "rm -rf $tmpdir" EXIT
    pushd ${tmpdir}
    curl -L -s -O ${GLIDE_URL} || fatal "failed to download 'GLIDE_URL': $?"
    for i in *.tar.gz; do
      [[ "$i" = "*.tar.gz" ]] && continue
      tar xzf "$i" -C ${tmpdir} --strip-components 1 && rm -r "$i"
    done
    popd
    mkdir -p ${BINARY_DIR}
    cp ${tmpdir}/* ${BINARY_DIR}/
  fi
}

function download_gometalinter() {
  if [[ ! -f "$GOMETALINTER" ]]; then
    verbose "   --> $GOMETALINTER"
    local tmpdir=`mktemp -d`
    trap_add "rm -rf $tmpdir" EXIT
    pushd ${tmpdir}
    curl -L -s -O ${GOMETALINTER_URL} || fatal "failed to download '$GOMETALINTER_URL': $?"
    for i in *.tar.gz; do
      [[ "$i" = "*.tar.gz" ]] && continue
      tar xzf "$i" -C ${tmpdir} --strip-components 1 && rm -r "$i"
    done
    popd
    mkdir -p ${BINARY_DIR}
    cp ${tmpdir}/* ${BINARY_DIR}/
  fi
}

function download_gox() {
  if [[ ! -x "$(command -v $GOX)" ]]; then
    verbose "   --> $GOX"
    go get github.com/mitchellh/gox || fatal "go get 'github.com/mitchellh/gox' failed: $?"
  fi
}

function download_goveralls() {
  if [[ -n "$TRAVIS" ]]; then
    if [[ ! -x "$(command -v goveralls)" ]]; then
      echo "   --> goveralls"
      go get github.com/mattn/goveralls || fatal "go get 'github.com/mattn/goveralls' failed: $?"
    fi
  fi
}

function download_upx() {
  if [[ ! -x "$(command -v $UPX)" ]]; then
    verbose "   --> $UPX "
    local upx_url="https://github.com/kadaan/upx/releases/download/20181231/upx_$PLATFORM"
    curl -o "$BINARY_DIR/upx" -sLO ${upx_url} || fatal "failed to download upx: $?"
    chmod +x "$BINARY_DIR/upx"
  fi
}

function download_binaries() {
  download_glide || fatal "failed to download 'glide': $?"
  download_gox || fatal "failed to download 'gox': $?"
  download_gometalinter || fatal "failed to download 'gometalinter': $?"
  download_goveralls || fatal "failed to download 'goveralls': $?"
  download_upx || fatal "failed to download 'upx': $?"
  export PATH=$PATH:${BINARY_DIR}
}

function usage() {
  echo "Usage: build.sh [OPTIONS ...]"
  echo "Builds the binary for your platform, or all supported platforms when '--build_all' is specified."
  echo ""
  echo "Options:"
  echo "    --build_all:   build binaries for all supported platforms"
  echo "    --clear_cache: clear the caches before running the build"
  echo "    --help:        display this help"
  echo ""
}

function parse_args() {
  for var in "${@}"; do
    case "$var" in
      --help)
        usage
        exit 0
      ;;
      --build_all)
        build_all=true
      ;;
      --clear_cache)
        if [[ -f ${GLIDE} ]]; then
          verbose "Clearing glide cache..."
          ${GLIDE} cc || fatal "failed to clear glide cache: $?"
        fi
        verbose "Deleting $BINARY_DIR ..."
        rm -rf ${BINARY_DIR} || fatal "failed to delete $BINARY_DIR: $?"
      ;;
    esac
  done
}

function run() {
  local build_all=false
  parse_args "$@"

  local revision=`git rev-parse HEAD`
  local branch=`git rev-parse --abbrev-ref HEAD`
  local host=`hostname`
  local buildDate=`date -u +"%Y-%m-%dT%H:%M:%SZ"`
  local go_version="$(cat ${BUILD_DIR}/.go-version)"
  go version | grep -q "go version go${go_version} " || fatal "go version is not ${go_version}"

  if [[ -z "$TRAVIS" ]]; then
    verbose "Cleanup dist..."
    rm -rf dist/*
  fi

  verbose "Fetching binaries..."
  download_binaries

  verbose "Getting dependencies..."
  ${GLIDE} install -v || fatal "glide install failed: $?"

  local gofiles=$(find . -path ./vendor -prune -o -print | grep '\.go$')

  verbose "Installing dependencies..."
  go install ./... || fatal "go install failed: $?"
  go test -i ./... || fatal "go test install failed: $?"

  verbose "Formatting source..."
  if [[ ${#gofiles[@]} -gt 0 ]]; then
    while read -r gofile; do
      gofmt -s -w $PWD/$gofile
    done <<< "$gofiles"
  fi

  if [[ -n "$TRAVIS" && -n "$(git status --porcelain)" ]]; then
    fatal "Source not formatted"
  fi

  verbose "Linting source..."
  ${GOMETALINTER} --disable-all --enable=vet --enable=gocyclo --cyclo-over=15 --enable=golint --min-confidence=.85 --enable=ineffassign --skip=Godeps --skip=vendor --skip=third_party --skip=testdata --vendor ./... || fatal "gometalinter failed: $?"

  verbose "Checking licenses..."
  local licRes=$(
  for file in $(find . -type f -iname '*.go' ! -path './vendor/*'); do
    head -n3 "${file}" | grep -Eq "(Copyright|generated|GENERATED)" || error "  Missing license in: ${file}"
  done;)
  if [[ -n "${licRes}" ]]; then
  	fatal "license header checking failed:\n${licRes}"
  fi

  verbose "Running tests..."
  if [[ -n "$TRAVIS" ]]; then
    goveralls -v -service=travis-ci -ignore=main.go,testutil/server.go,testutil/golden.go || fatal "goveralls: $?"
  else
    go test -v ./... || fatal "$gopackage tests failed: $?"
  fi

  XC_ARCH=${XC_ARCH:-"386 amd64"}
  XC_OS=${XC_OS:-"darwin linux windows"}
  if [[ -z "$TRAVIS" && "$build_all" != "true" ]]; then
    XC_OS=$(go env GOOS)
    XC_ARCH=$(go env GOARCH)
  fi

  verbose "Building binaries..."
  ${GOX} -os="${XC_OS}" -arch="${XC_ARCH}" -osarch="!darwin/arm !darwin/arm64" -ldflags "-s -w -X github.com/kadaan/acurite_exporter/vendor/github.com/prometheus/common/version.Version=$VERSION -X github.com/kadaan/acurite_exporter/vendor/github.com/prometheus/common/version.Revision=$revision -X github.com/kadaan/acurite_exporter/vendor/github.com/prometheus/common/version.Branch=$branch -X github.com/kadaan/acurite_exporter/vendor/github.com/prometheus/common/version.BuildUser=$USER@$host -X github.com/kadaan/acurite_exporter/vendor/github.com/prometheus/common/version.BuildDate=$buildDate" -output="dist/{{.Dir}}_{{.OS}}_{{.Arch}}" || fatal "gox failed: $?"

  verbose "Compressing binaries..."
  for f in dist/*; do
    ${UPX} --best ${f} || fatal "failed to compress binary '$f': $?"
  done

  if [[ -n "$TRAVIS" ]]; then
    verbose "Creating archives..."
    cd dist
    set -x
    for f in *; do
      local filename=$(basename "$f")
      local extension="${filename##*.}"
      local filename="${filename%.*}"
      if [[ "$filename" != "$extension" ]] && [[ -n "$extension" ]]; then
        extension=".$extension"
      else
        extension=""
      fi
      local archivename="$filename.tar.gz"
      verbose "   --> $archivename"
      local genericname="acurite_exporter$extension"
      mv -f "$f" "$genericname"
      tar -czf ${archivename} "$genericname"
      rm -rf "$genericname"
    done
  fi
}

run "$@"
