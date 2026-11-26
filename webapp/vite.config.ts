import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { nginxUiPlugin } from '@nginxui/plugin-sdk/vite'

export default defineConfig({
  plugins: [
    vue(),
    nginxUiPlugin({
      id: 'io.github.3130585774.fail2ban',
      entry: 'src/index.ts',
    }),
  ],
})
