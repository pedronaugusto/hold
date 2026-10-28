const std = @import("std");

/// What a project that depends on hold builds: the `hold` module, over
/// aegis, warp (every codec), airlock (extraction's files) and xenoglyph
/// (names as text). The tests, fuzz targets, example, benchmarks and gate
/// are `dev`'s.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    b.modules.put(b.graph.arena, "hold", holdModule(b, target, optimize)) catch @panic("OOM");
}

/// hold's development: its tests, the fuzz targets, the example and the
/// benchmarks, under preflight's gate. Run through bay.
pub fn dev(b: *std.Build, tools: type) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filter = b.option([]const u8, "test-filter", "Select tests by name");
    const package = b.dependency("hold", .{ .target = target, .optimize = optimize });
    const p = package.builder;
    const module = package.module("hold");
    const filters: []const []const u8 = if (test_filter) |filter| &.{filter} else &.{};

    const test_step = b.step("test", "Run the tests, the fuzz targets' corpora and the example");
    const check = b.step("check", "Compile the tests, example and benchmarks without running them");

    const tests = suite(b, p, "hold-tests", target, optimize, filters);
    const unit = b.step("unit", "Run the test suite alone");
    unit.dependOn(&b.addRunArtifact(tests).step);
    test_step.dependOn(unit);
    check.dependOn(&tests.step);

    // The fuzz targets alone, every parser and decoder of the package: what
    // the fuzzer runs (`bay parsers --fuzz`). The suite runs them over their
    // corpora too.
    const fuzz = suite(b, p, "hold-fuzz", target, optimize, if (test_filter) |filter| &.{filter} else &.{"fuzz_test."});
    b.step("parsers", "Run the fuzz targets alone").dependOn(&b.addRunArtifact(fuzz).step);
    check.dependOn(&fuzz.step);

    // examples/usage.zig is also README.md's Usage blocks (bay docs --
    // usage), so the code a reader copies is code the tests run.
    const example = b.addExecutable(.{
        .name = "usage",
        .root_module = b.createModule(.{ .root_source_file = p.path("examples/usage.zig"), .target = target, .optimize = optimize, .imports = &.{.{ .name = "hold", .module = module }} }),
    });
    const example_run = b.addRunArtifact(example);
    example_run.setCwd(p.path("."));
    const examples = b.step("examples", "Build and run the usage example");
    examples.dependOn(&example_run.step);
    test_step.dependOn(examples);
    check.dependOn(&example.step);
    b.getInstallStep().dependOn(check);

    // The writer behind trials' interop check (hold/src/interop.zig), where
    // the rivals' readers read what hold writes; run by hand.
    const interop = b.addExecutable(.{
        .name = "interop-write",
        .root_module = b.createModule(.{ .root_source_file = p.path("testdata/tools/write.zig"), .target = target, .optimize = optimize, .imports = &.{.{ .name = "hold", .module = module }} }),
    });
    b.step("interop-write", "Build the writer trials' interop check runs").dependOn(&b.addInstallArtifact(interop, .{}).step);
    check.dependOn(&interop.step);

    // testdata/testdata.zig, the interop corpus's index, written again
    // after an archive or a `.hold` file comes or goes; run by hand.
    const index = b.addExecutable(.{
        .name = "testdata-index",
        .root_module = b.createModule(.{ .root_source_file = p.path("testdata/tools/index.zig"), .target = target, .optimize = optimize }),
    });
    const index_run = b.addRunArtifact(index);
    index_run.addDirectoryArg2(p.path("testdata"), .{});
    b.step("testdata-index", "Write testdata/testdata.zig, the interop corpus's index").dependOn(&index_run.step);
    check.dependOn(&index.step);

    tools.preflight.addCi(b, p, .{
        .tests = test_step,
        .portable_tests = true,
        // The release tier fuzzes every parser.
        .hardened = .{ .fuzz_step = "parsers", .tsan_step = "unit", .fuzz_iterations = 3000 },
        // `bay bench` times them in ReleaseFast, by hand; never timed in CI,
        // where `bay test` runs each row once.
        .bench = .{
            .programs = &.{.{ .name = "hold-bench", .source = "bench/main.zig" }},
            .imports = benchImports,
            .target = target,
            .optimize = optimize,
        },
    });
    // A project that depends on hold by path, with only the packages hold
    // needs: the build a consumer gets.
    tools.preflight.addConsumerCheck(b, p, .{
        .package = "hold",
        .program = p.path("ci/consumer.zig"),
        .packages = &.{
            p.dependency("aegis", .{ .target = target, .optimize = optimize }),
            p.dependency("warp", .{ .target = target, .optimize = optimize }),
            p.dependency("airlock", .{ .target = target, .optimize = optimize }),
            p.dependency("xenoglyph", .{ .target = target, .optimize = optimize }),
        },
        .modules = &.{"hold"},
    });
}

/// `hold` and the packages its sources import, built for `target` and
/// `optimize`.
fn holdModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("src/hold.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSourceImports(b, module, target, optimize);
    return module;
}

fn addSourceImports(b: *std.Build, module: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) void {
    for ([_][]const u8{ "aegis", "warp", "airlock", "xenoglyph" }) |name| {
        module.addImport(name, b.dependency(name, .{ .target = target, .optimize = optimize }).module(name));
    }
}

/// The tests: src/tests.zig, the one root, over hold's sources and the
/// interop corpus under testdata/, with shakedown for test support.
fn suite(b: *std.Build, p: *std.Build, name: []const u8, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize, filters: []const []const u8) *std.Build.Step.Compile {
    const module = b.createModule(.{
        .root_source_file = p.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSourceImports(p, module, target, optimize);
    module.addImport("shakedown", b.dependency("shakedown", .{ .target = target, .optimize = optimize }).module("shakedown"));
    module.addAnonymousImport("testdata", .{ .root_source_file = p.path("testdata/testdata.zig") });
    return b.addTest(.{ .name = name, .filters = filters, .root_module = module });
}

/// hold again, in the mode a benchmark builds in: an imported module keeps
/// its own mode, so a ReleaseFast benchmark over the Debug module would
/// time the Debug module. `b` is the development build.
fn benchImports(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) []const std.Build.Module.Import {
    const p = b.dependency("hold", .{ .target = target, .optimize = optimize }).builder;
    return b.allocator.dupe(std.Build.Module.Import, &.{
        .{ .name = "hold", .module = holdModule(p, target, optimize) },
        .{ .name = "warp", .module = p.dependency("warp", .{ .target = target, .optimize = optimize }).module("warp") },
        .{ .name = "aegis", .module = p.dependency("aegis", .{ .target = target, .optimize = optimize }).module("aegis") },
    }) catch @panic("OOM");
}
