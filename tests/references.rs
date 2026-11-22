//! The reference implementations the comparison tests drive, each found or
//! reported missing. Under the `FILE_ACL_REQUIRE_*` variables these fail
//! where a reference is missing, so a run that sets them is one in which every
//! comparison ran.

mod support;

#[test]
fn the_kernel_holds_lists_in_the_scratch_directory() {
    let dir = support::scratch("references-kernel");
    let _ = support::kernel(&dir);
}

#[test]
fn the_kernel_holds_lists_inside_a_user_namespace() {
    let dir = support::scratch("references-user-namespace");
    let _ = support::kernel_in_user_namespace(&dir);
}

#[test]
fn the_kernel_holds_lists_on_a_tmpfs() {
    let dir = support::scratch("references-tmpfs");
    let _ = support::kernel_on_tmpfs(&dir);
}

#[test]
fn libacl_loads() {
    let _ = support::libacl();
}

#[test]
fn gnu_tar_runs() {
    let _ = support::gnu_tar();
}

#[test]
fn the_kernel_translates_lists_across_an_id_map() {
    let dir = support::scratch("references-id-map");
    let _ = support::kernel_across_an_id_map(&dir);
}

#[test]
fn bsdtar_runs() {
    let _ = support::bsdtar();
}
