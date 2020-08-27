package seccomp

import (
	"fmt"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

var (
	goArchToSeccompArchMap = map[string]Arch{
		"386":         ArchX86,
		"amd64":       ArchX86_64,
		"amd64p32":    ArchX32,
		"arm":         ArchARM,
		"arm64":       ArchAARCH64,
		"mips":        ArchMIPS,
		"mips64":      ArchMIPS64,
		"mips64le":    ArchMIPSEL64,
		"mips64p32":   ArchMIPS64N32,
		"mips64p32le": ArchMIPSEL64N32,
		"mipsle":      ArchMIPSEL,
		"ppc":         ArchPPC,
		"ppc64":       ArchPPC64,
		"ppc64le":     ArchPPC64LE,
		"s390":        ArchS390,
		"s390x":       ArchS390X,
	}
	specArchToLibseccompArchMap = map[specs.Arch]string{
		specs.ArchX86:         "x86",
		specs.ArchX86_64:      "amd64",
		specs.ArchX32:         "x32",
		specs.ArchARM:         "arm",
		specs.ArchAARCH64:     "arm64",
		specs.ArchMIPS:        "mips",
		specs.ArchMIPS64:      "mips64",
		specs.ArchMIPS64N32:   "mips64n32",
		specs.ArchMIPSEL:      "mipsel",
		specs.ArchMIPSEL64:    "mipsel64",
		specs.ArchMIPSEL64N32: "mipsel64n32",
		specs.ArchPPC:         "ppc",
		specs.ArchPPC64:       "ppc64",
		specs.ArchPPC64LE:     "ppc64le",
		specs.ArchS390:        "s390",
		specs.ArchS390X:       "s390x",
	}
	specActionToSeccompActionMap = map[specs.LinuxSeccompAction]Action{
		specs.ActKill: ActKill,
		// TODO: wait for this PR to get merged:
		// https://github.com/opencontainers/runtime-spec/pull/1064
		// specs.ActKillProcess   ActKillProcess,
		// specs.ActKillThread   ActKillThread,
		specs.ActErrno: ActErrno,
		specs.ActTrap:  ActTrap,
		specs.ActAllow: ActAllow,
		specs.ActTrace: ActTrace,
		specs.ActLog:   ActLog,
	}
	specOperatorToSeccompOperatorMap = map[specs.LinuxSeccompOperator]Operator{
		specs.OpNotEqual:     OpNotEqual,
		specs.OpLessThan:     OpLessThan,
		specs.OpLessEqual:    OpLessEqual,
		specs.OpEqualTo:      OpEqualTo,
		specs.OpGreaterEqual: OpGreaterEqual,
		specs.OpGreaterThan:  OpGreaterThan,
		specs.OpMaskedEqual:  OpMaskedEqual,
	}
)

// GoArchToSeccompArch converts a runtime.GOARCH to a seccomp `Arch`. The
// function returns an error if the architecture conversion is not supported.
func GoArchToSeccompArch(goArch string) (Arch, error) {
	arch, ok := goArchToSeccompArchMap[goArch]
	if !ok {
		return "", fmt.Errorf("unsupported go arch provided: %s", goArch)
	}
	return arch, nil
}

// specToSeccomp converts a `LinuxSeccomp` spec into a `Seccomp` struct and the
// corresponding libseccomp architectures.
func specToSeccomp(config *specs.LinuxSeccomp) (*Seccomp, []string, error) {
	res := &Seccomp{
		Syscalls: []*Syscall{},
	}

	libseccompArchitectures := []string{}
	if len(config.Architectures) > 0 {
		for _, arch := range config.Architectures {
			newArch, err := specArchToLibseccompArch(arch)
			if err != nil {
				return nil, nil, errors.Wrap(err, "convert spec arch")
			}
			libseccompArchitectures = append(libseccompArchitectures, newArch)
		}
	}

	// Convert default action
	newDefaultAction, err := specActionToSeccompAction(config.DefaultAction)
	if err != nil {
		return nil, nil, errors.Wrap(err, "convert default action")
	}
	res.DefaultAction = newDefaultAction

	// Loop through all syscall blocks and convert them to the internal format
	for _, call := range config.Syscalls {
		newAction, err := specActionToSeccompAction(call.Action)
		if err != nil {
			return nil, nil, errors.Wrap(err, "convert action")
		}

		for _, name := range call.Names {
			newCall := Syscall{
				Name:     name,
				Action:   newAction,
				ErrnoRet: call.ErrnoRet,
				Args:     []*Arg{},
			}

			// Loop through all the arguments of the syscall and convert them
			for _, arg := range call.Args {
				newOp, err := specOperatorToSeccompOperator(arg.Op)
				if err != nil {
					return nil, nil, errors.Wrap(err, "convert operator")
				}

				newArg := Arg{
					Index:    arg.Index,
					Value:    arg.Value,
					ValueTwo: arg.ValueTwo,
					Op:       newOp,
				}

				newCall.Args = append(newCall.Args, &newArg)
			}
			res.Syscalls = append(res.Syscalls, &newCall)
		}
	}

	return res, libseccompArchitectures, nil
}

// specArchToLibseccompArch converts a spec arch into a libseccomp one.
func specArchToLibseccompArch(arch specs.Arch) (string, error) {
	if res, ok := specArchToLibseccompArchMap[arch]; ok {
		return res, nil
	}
	return "", errors.Errorf(
		"architecture %q is not valid for libseccomp", arch,
	)
}

// specActionToSeccompAction converts a spec action into a seccomp one.
func specActionToSeccompAction(action specs.LinuxSeccompAction) (Action, error) {
	if res, ok := specActionToSeccompActionMap[action]; ok {
		return res, nil
	}
	return "", errors.Errorf(
		"spec action %q is not valid internal action", action,
	)
}

// specOperatorToSeccompOperator converts a spec operator into a seccomp one.
func specOperatorToSeccompOperator(operator specs.LinuxSeccompOperator) (Operator, error) {
	if op, ok := specOperatorToSeccompOperatorMap[operator]; ok {
		return op, nil
	}
	return "", errors.Errorf(
		"spec operator %q is not a valid internal operator", operator,
	)
}
