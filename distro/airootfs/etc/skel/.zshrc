# ============================================================
# Cerberix Linux — Zsh Configuration
# ============================================================

# History
HISTFILE=~/.zsh_history
HISTSIZE=10000
SAVEHIST=10000
setopt appendhistory sharehistory hist_ignore_dups hist_ignore_space

# Completion
autoload -Uz compinit && compinit
zstyle ':completion:*' menu select
zstyle ':completion:*' matcher-list 'm:{a-z}={A-Z}'

# Keybinds
bindkey -e
bindkey '^[[A' history-search-backward
bindkey '^[[B' history-search-forward
bindkey '^[[H' beginning-of-line
bindkey '^[[F' end-of-line
bindkey '^[[3~' delete-char

# Aliases
alias ls='eza --icons --group-directories-first'
alias ll='eza -la --icons --group-directories-first'
alias lt='eza --tree --level=2 --icons'
alias cat='bat --paging=never'
alias grep='grep --color=auto'
alias df='df -h'
alias du='du -h'
alias free='free -h'
alias update='cerberix-update'
alias fetch='fastfetch'
alias ip='ip -c'

# Safety
alias rm='rm -I'
alias mv='mv -i'
alias cp='cp -i'

# Cerberix
alias shield='cerberix-shield-status'
alias fw='sudo ufw status numbered'

# Start Starship prompt
eval "$(starship init zsh)"

# First boot check
[[ -f /usr/local/bin/cerberix-firstboot ]] && cerberix-firstboot

# Show fastfetch on new terminal
fastfetch 2>/dev/null
