{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.pantosmime;
in {
  options.services.pantosmime = let
    inherit (lib) types mkEnableOption mkOption;
  in {
    enable = mkEnableOption "pantosmime, a plain-text to S/MIME encryption milter";
    package = mkOption {
      default = pkgs.callPackage ./default.nix {};
      defaultText = "pkgs.pantosmime";
      type = types.package;
      description = "pantosmime package to use";
    };

    bindAddress = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "IP address on which pantosmime should listen.";
    };
    port = mkOption {
      type = types.port;
      default = 22666;
      description = "Listen port for pantosmime.";
    };

    user = mkOption {
      type = types.str;
      default = "pantosmime";
      description = "User which runs the pantosmimed service.";
    };

    group = mkOption {
      type = types.str;
      default = "pantosmime";
      description = "Group which runs the pantosmimed service.";
    };

    logLevel = lib.mkOption {
      type = lib.types.enum [
        "error"
        "warn"
        "info"
        "debug"
        "trace"
      ];
      default = "info";
      description = "Log level";
    };

    certificateDirectory = lib.mkOption {
      type = types.str;
      default = "/var/lib/pantosmime/certs";
      description = "Directory where to store the collected S/MIME certificates.";
    };

    addresses = lib.mkOption {
      type = types.listOf types.str;
      description = "List of emails to forcibly encrypt messages for.";
    };
  };
  config = lib.mkIf cfg.enable {
    users.users = lib.optionalAttrs (cfg.user == "pantosmime") {
      pantosmime = {
        group = "pantosmime";
        isSystemUser = true;
      };
    };

    users.groups = lib.optionalAttrs (cfg.group == "pantosmime") {
      pantosmime = {};
    };

    systemd.tmpfiles.rules = [
      "d ${cfg.certificateDirectory} 750 ${cfg.user} ${cfg.group} -"
    ];

    systemd.services.pantosmime = {
      wantedBy = ["multi-user.target"];
      description = "S/MIME encryption milter";
      environment = {
        RUST_LOG = cfg.logLevel;
      };
      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        Type = "simple";
        ExecStart =
          "${cfg.package}/bin/pantosmimed -l ${cfg.bindAddress}:${builtins.toString cfg.port} -c ${cfg.certificateDirectory} "
          + lib.concatMapStringsSep " " (m: "-a ${m}") cfg.addresses;
        Restart = "always";
        RestartSec = "10";

        # Hardening
        AmbientCapabilities = lib.mkIf (cfg.port < 1024) ["CAP_NET_BIND_SERVICE"];
        CapabilityBoundingSet =
          if (cfg.port < 1024)
          then ["CAP_NET_BIND_SERVICE"]
          else [""];
        DeviceAllow = [""];
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        PrivateDevices = true;
        # A private user cannot have process capabilities on the host's user
        # namespace and thus CAP_NET_BIND_SERVICE has no effect.
        PrivateUsers = cfg.port >= 1024;
        ProcSubset = "pid";
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        ReadWritePaths = [cfg.certificateDirectory];
        RemoveIPC = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
        UMask = "0027";
      };
    };
  };
}
