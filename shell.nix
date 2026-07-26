{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
    buildInputs = with pkgs; [
        act
        docker
        cargo
        rustc
        gdb
        rust-analyzer
        rustup
        sqlite
    ];
}