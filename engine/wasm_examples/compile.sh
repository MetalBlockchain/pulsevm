if ! [[ "$0" =~ engine/wasm_examples/compile.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

PULSEVM_WASM_EXAMPLES_PATH=$(
  cd "$(dirname "${BASH_SOURCE[0]}")"
  pwd
)

for i in $PULSEVM_WASM_EXAMPLES_PATH/*.ts; do
    asc $i --outFile $(echo "$i" | cut -f 1 -d '.').wasm -O3 --runtime stub
done