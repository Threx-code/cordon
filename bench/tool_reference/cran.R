# renv's own reading of each renv.lock (renv::lockfile_read): every package, its version and source.
for (repo in list.dirs("/data/cran", recursive = FALSE)) {
  dir.create(file.path(repo, ".reference"), showWarnings = FALSE)
  out <- file(file.path(repo, ".reference", "renv.tsv"), "w")
  locks <- list.files(repo, pattern = "^renv\\.lock$", recursive = TRUE, all.files = TRUE)
  for (lock in locks[!grepl("^\\.reference", locks)]) {
    result <- tryCatch({
      packages <- renv::lockfile_read(file.path(repo, lock))$Packages
      for (p in packages) {
        writeLines(paste(lock, p$Package, ifelse(is.null(p$Version), "", p$Version),
                         ifelse(is.null(p$Source), "", p$Source), sep = "\t"), out)
      }
    }, error = function(e) writeLines(paste("error", lock, conditionMessage(e), sep = "\t"), out))
  }
  close(out)
}
