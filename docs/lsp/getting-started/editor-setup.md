---
title: "Editor Setup"
description: "Configure the Achronyme LSP server in your editor"
section: "lsp-getting-started"
order: 2
---

# Editor Setup Guide

This guide shows how to configure the Achronyme LSP server in popular editors.

## VS Code

### Using the Extension (Recommended)

The easiest way is to use an official Achronyme extension when available.

For now, use the manual setup below.

### Manual Setup

1. **Install the LSP Server**

   ```bash
   cargo install --path crates/achronyme-lsp
   ```

2. **Install the "LSP Client" Extension**

   Open VS Code extensions (`Ctrl+Shift+X` / `Cmd+Shift+X`) and search for:
   - "LSP Client" by Microsoft
   - Or "LSP" by Fabio Dal Sasso

3. **Configure the LSP Client**

   Add to your VS Code `settings.json` (`Ctrl+,` → search "settings.json"):

   ```json
   "lsp": {
     "languages": {
       "achronyme": {
         "command": "achronyme-lsp",
         "args": ["--stdio"],
         "filetypes": ["achronyme"],
         "initializationOptions": {
           "debug": false
         }
       }
     }
   }
   ```

   Or for the alternative LSP extension by Fabio Dal Sasso:

   ```json
   "[achronyme]": {
     "editor.defaultFormatter": "achronyme.formatter"
   },
   "lsp": {
     "achronyme": {
       "command": "achronyme-lsp",
       "args": ["--stdio"],
       "filetypes": ["achronyme"]
     }
   }
   ```

4. **Associate .soc Files**

   Add to `settings.json`:

   ```json
   "files.associations": {
     "*.soc": "achronyme"
   }
   ```

5. **Restart VS Code**

   The LSP should connect automatically when you open a `.soc` file.

### Verifying the Connection

When a `.soc` file is open:

1. Look at the bottom status bar
2. You should see "Achronyme" or "LSP" status indicator
3. Hover over code to see if tooltips appear
4. Try `Ctrl+Space` for completions

### Troubleshooting VS Code

**LSP doesn't connect:**
- Check the Output panel (`Ctrl+Shift+U`) and look for LSP output
- Verify the LSP binary path is correct: `which achronyme-lsp` (Linux/macOS)
- Try specifying the full path in settings.json

**No completions:**
- Ensure trigger characters are configured
- Try pressing `Ctrl+Shift+I` to open IntelliSense

## Neovim

Neovim has native LSP support via `nvim-lspconfig`.

### Setup with nvim-lspconfig

1. **Install LSP Server**

   ```bash
   cargo install --path crates/achronyme-lsp
   ```

2. **Install nvim-lspconfig Plugin**

   Using packer.nvim:

   ```lua
   use 'neovim/nvim-lspconfig'
   ```

   Or vim-plug:

   ```vim
   Plug 'neovim/nvim-lspconfig'
   ```

3. **Configure in init.lua**

   Add to your `~/.config/nvim/init.lua`:

   ```lua
   local lspconfig = require('lspconfig')

   -- Create a custom configuration for Achronyme
   local configs = require 'lspconfig.configs'

   if not configs.achronyme then
     configs.achronyme = {
       default_config = {
         cmd = { 'achronyme-lsp', '--stdio' },
         filetypes = { 'achronyme' },
         root_dir = lspconfig.util.find_git_ancestor,
         settings = {
           achronyme = {
             debug = false
           }
         }
       }
     }
   end

   lspconfig.achronyme.setup {}
   ```

4. **Set File Type**

   Add to `~/.config/nvim/init.lua`:

   ```lua
   vim.filetype.add({
     extension = {
       soc = 'achronyme'
     }
   })
   ```

   Or in `~/.config/nvim/ftdetect/achronyme.vim`:

   ```vim
   autocmd BufRead,BufNewFile *.soc set filetype=achronyme
   ```

5. **Test the Setup**

   Open a `.soc` file and run:

   ```vim
   :LspInfo
   ```

   You should see the Achronyme LSP client listed.

### Keybindings for Neovim

Add useful keybindings to your `init.lua`:

```lua
local on_attach = function(client, bufnr)
  local bufopts = { noremap=true, silent=true, buffer=bufnr }
  vim.keymap.set('n', 'gd', vim.lsp.buf.definition, bufopts)
  vim.keymap.set('n', 'K', vim.lsp.buf.hover, bufopts)
  vim.keymap.set('n', 'gr', vim.lsp.buf.references, bufopts)
  vim.keymap.set('n', 'gi', vim.lsp.buf.implementation, bufopts)
  vim.keymap.set('n', '<C-k>', vim.lsp.buf.signature_help, bufopts)
  vim.keymap.set('n', '<leader>f', vim.lsp.buf.format, bufopts)
end

lspconfig.achronyme.setup {
  on_attach = on_attach
}
```

## Emacs

### Setup with lsp-mode

1. **Install LSP Server**

   ```bash
   cargo install --path crates/achronyme-lsp
   ```

2. **Install lsp-mode**

   Using use-package (recommended):

   ```elisp
   (use-package lsp-mode
     :ensure t
     :commands (lsp lsp-deferred))
   ```

   Or with package.el:

   ```elisp
   M-x package-install RET lsp-mode RET
   ```

3. **Register Achronyme Language**

   Add to your `~/.emacs.d/init.el`:

   ```elisp
   (use-package lsp-mode
     :ensure t
     :commands (lsp lsp-deferred)
     :hook
     ((achronyme-mode . lsp-deferred))
     :init
     (lsp-register-client
       (make-lsp-client :new-connection
         (lsp-stdio-connection
           '("achronyme-lsp" "--stdio"))
         :server-id 'achronyme
         :activation-fn (lsp-activate-on "achronyme")
         :initialization-options
         '((debug . nil)))))
   ```

4. **Define Achronyme Mode**

   Add to your `~/.emacs.d/init.el`:

   ```elisp
   (define-derived-mode achronyme-mode prog-mode "Achronyme"
     "Major mode for Achronyme files"
     (setq-local indent-tabs-mode nil
                 tab-width 4))

   (add-to-list 'auto-mode-alist '("\\.soc\\'" . achronyme-mode))
   ```

5. **Install Complementary Packages**

   For better experience, also install:

   ```elisp
   (use-package lsp-ui
     :ensure t
     :commands lsp-ui-mode)

   (use-package company
     :ensure t
     :init (global-company-mode))

   (use-package company-lsp
     :ensure t
     :commands company-lsp)
   ```

### Emacs Keybindings

Key features available via `lsp-mode`:

| Key | Action |
|-----|--------|
| `C-c l d` | Go to definition |
| `C-c l f` | Find references |
| `C-c l h` | Hover documentation |
| `C-c l f` | Format buffer |
| `M-x completion-at-point` | Code completion |

## Vim

### Setup with vim-lsp

1. **Install vim-lsp Plugin**

   Using vim-plug:

   ```vim
   Plug 'prabirshrestha/vim-lsp'
   ```

2. **Configure in .vimrc**

   Add to your `~/.vimrc`:

   ```vim
   if executable('achronyme-lsp')
     au User lsp_setup call lsp#register_server({
       \ 'name': 'achronyme',
       \ 'cmd': {server_info -> ['achronyme-lsp', '--stdio']},
       \ 'whitelist': ['achronyme'],
       \ })
   endif

   augroup achronyme_filetype
     autocmd!
     autocmd BufNewFile,BufRead *.soc set filetype=achronyme
   augroup END
   ```

3. **Test**

   Open a `.soc` file and check:

   ```vim
   :LspStatus
   ```

## Sublime Text

### Setup with LSP Package

1. **Install LSP Package**

   Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):
   - Type "Package Control: Install Package"
   - Search for "LSP"
   - Install it

2. **Configure LSP for Achronyme**

   Open Settings (`Preferences` → `Package Settings` → `LSP` → `Settings`):

   ```json
   {
     "clients": {
       "achronyme": {
         "enabled": true,
         "command": ["achronyme-lsp", "--stdio"],
         "languages": [
           {
             "languageId": "achronyme",
             "scopes": ["source.achronyme"],
             "syntaxes": ["Packages/Achronyme/Achronyme.sublime-syntax"]
           }
         ]
       }
     }
   }
   ```

## Verifying the Setup

To verify the LSP server is working in any editor:

1. **Open a `.soc` file**
2. **Check for these signs of successful connection:**
   - Editor shows no connection errors
   - Hover over a keyword (e.g., `let`, `if`) shows documentation
   - Try code completion with the editor's completion trigger

## Performance Tips

If the LSP server feels slow:

1. **Check your `.soc` file size**
   - Very large files (>10k lines) may take longer to parse

2. **Enable debug mode to diagnose:**
   ```
   --debug flag in server command
   ```

3. **Check your editor's LSP client settings:**
   - Reduce request timeout if too aggressive
   - Check system resources (memory, CPU)

## Getting Help

If editor setup doesn't work:

1. Check [Editor Troubleshooting](../advanced/troubleshooting.md#editor-setup)
2. Enable debug logging in your editor
3. Report issues with:
   - Your editor version
   - Your OS
   - Steps to reproduce

---

**Next**: [Configuration](configuration.md)
