{ pkgs
, lib
, buildGoModule
, flint3
, gmp
, mpfr
, pkg-config
, static ? true,
}:

buildGoModule {
  pname = "csppsolver";
  version = "2.2.0";
  subPackages = [ "./cmd/csppsolver" ];

  src = ./.;
  proxyVendor = true;
  vendorHash = null;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ gmp mpfr flint3 ];

  ldflags = lib.optionals static [ "-linkmode=external" "-extldflags=-static" ];

  CGO_LDFLAGS = "-O2 -g -lflint -lm";
  CGO_ENABLED = 1;
}
