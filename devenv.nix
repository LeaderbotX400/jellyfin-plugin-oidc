{
  pkgs,
  lib,
  config,
  ...
}:
{
  # https://devenv.sh/languages/
  languages.dotnet = {
    enable = true;
    package = pkgs.dotnet-sdk_10;
  };

  # See full reference at https://devenv.sh/reference/options/
}
