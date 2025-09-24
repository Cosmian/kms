curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# For some reason, the script stops here.
# Is it because rustup installation calls exit?
. $HOME/.cargo/env

export LD_LIBRARY_PATH=/lib
