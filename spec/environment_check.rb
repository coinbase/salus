apps = %w(bandit sift cargo semgrep gosec npm) # cargo-audit
missing_apps = apps.map { |app|`which #{app}`.empty? ? app : nil }.compact
raise "Salus requires #{missing_apps.to_sentence()} to be installed and available on the shell." if missing_apps.any?

# brew install semgrep
# pip3 install bandit
# brew install sift

#RuntimeError:
#  Salus requires bandit, sift, semgrep, and gosec to be installed and available on the shell.