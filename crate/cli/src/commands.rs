use clap::{Parser, Subcommand};

use crate::actions::{
    access::AccessAction,
    certificates::CertificatesCommands,
    cover_crypt::CovercryptCommands,
    elliptic_curves::EllipticCurveCommands,
    login::LoginAction,
    logout::LogoutAction,
    markdown::MarkdownAction,
    new_database::NewDatabaseAction,
    shared::{GetAttributesAction, LocateObjectsAction},
    symmetric::SymmetricCommands,
    version::ServerVersionAction,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: CliCommands,
}

#[derive(Subcommand)]
pub enum CliCommands {
    #[command(subcommand)]
    AccessRights(AccessAction),
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[command(subcommand)]
    Certificates(CertificatesCommands),
    #[command(subcommand)]
    Ec(EllipticCurveCommands),
    GetAttributes(GetAttributesAction),
    Locate(LocateObjectsAction),
    NewDatabase(NewDatabaseAction),
    ServerVersion(ServerVersionAction),
    #[command(subcommand)]
    Sym(SymmetricCommands),
    Login(LoginAction),
    Logout(LogoutAction),
    #[clap(hide = true)]
    Markdown(MarkdownAction),
}
