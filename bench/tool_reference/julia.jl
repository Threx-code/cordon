# Pkg's own reading of each Project.toml (and its Manifest.toml where committed). The last column
# says what Pkg knows of each entry: a standard library (shipped with Julia, never downloaded), a
# path or repository source, or a registered package.
import Pkg
kind(uuid, path) = Pkg.Types.is_stdlib(uuid) ? "stdlib" : path === nothing ? "registry" : "path"
for repo in readdir("/data/julia"; join=true)
    isdir(repo) || continue
    mkpath(joinpath(repo, ".reference"))
    open(joinpath(repo, ".reference", "julia.tsv"), "w") do out
        for (root, _, files) in walkdir(repo)
            occursin(".reference", root) && continue
            "Project.toml" in files || continue
            rel = relpath(root, repo)
            try
                project = Pkg.Types.read_project(joinpath(root, "Project.toml"))
                sourced(name) = haskey(project.sources, name) && haskey(project.sources[name], "path")
                for (name, uuid) in merge(project.deps, project.weakdeps, project.extras)
                    println(out, rel, "\tdeps\t", name, "\t", uuid, "\t", kind(uuid, sourced(name) ? "" : nothing))
                end
                if "Manifest.toml" in files
                    manifest = Pkg.Types.read_manifest(joinpath(root, "Manifest.toml"))
                    for (uuid, entry) in manifest
                        println(out, rel, "\tmanifest\t", entry.name, "\t", uuid, "\t", kind(uuid, entry.path))
                    end
                end
            catch err
                println(out, rel, "\terror\t", replace(sprint(showerror, err), "\n" => " ")[1:min(end, 200)])
            end
        end
    end
end
