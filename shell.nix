{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    clippy
    rustfmt
    just
    sqlite
  ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
    libiconv
  ];

  RUST_BACKTRACE = "1";
}
