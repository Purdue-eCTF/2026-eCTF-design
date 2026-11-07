{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  packages = [
    pkgs.pkgsCross.arm-embedded.buildPackages.gcc
    pkgs.python3
  ];
}
