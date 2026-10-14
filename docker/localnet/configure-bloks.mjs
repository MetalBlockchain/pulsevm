import { readFileSync, writeFileSync } from 'node:fs';

// Fail explicitly if an upstream source change invalidates these adaptations.
function replaceOnce(path, before, after) {
  const source = readFileSync(path, 'utf8');
  if (source.split(before).length !== 2) {
    throw new Error(`Expected one localnet configuration hook in ${path}`);
  }
  writeFileSync(path, source.replace(before, after));
}

replaceOnce(
  'apps/frontend/src/App.vue',
  'const needSetup = ref(chainIsLocal.value)',
  'const needSetup = ref(chainIsLocal.value && !window.PULSEVM_LOCALNET)',
);
replaceOnce(
  'apps/frontend/src/stores/settings.ts',
  "needSetup: constants.CHAIN === 'local'",
  "needSetup: constants.CHAIN === 'local' && !window.PULSEVM_LOCALNET",
);
