{
  inputs = {
    nixpkgs = {
      type = "github";
      owner = "NixOS";
      repo = "nixpkgs";
      rev = "43a7d62e073e39dfe21b83c62720ff1c733e6ad3";
    };
  };

  outputs = { self, nixpkgs }: {
    defaultPackage.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.stdenv.mkDerivation {

      name = "lmdnsd";
      src = ./.;

      buildDepsDeps = [
        nixpkgs.legacyPackages.x86_64-linux.ragel
      ];

      buildInputs = [ 
      ];

      installFlags = [ "DESTDIR=$(out)" "PREFIX=/" ];

    };
  };
}
