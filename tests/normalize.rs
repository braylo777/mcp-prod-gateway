//! Normalization, name skeletons and edit distance used by the deep rules.

use mcpgw::policy::{name_skeleton, normalize, osa_distance};

macro_rules! norm {
    ($($n:ident: $input:expr => $want:expr;)*) => {$(
        #[test]
        fn $n() {
            assert_eq!(normalize($input), $want);
        }
    )*};
}

norm! {
    n_plain: "Hello World" => "hello world";
    n_whitespace: "  a \n\t b  " => "a b";
    n_cyrillic: "\u{0456}gn\u{043e}re" => "ignore";
    n_greek: "\u{03bf}k" => "ok";
    n_fullwidth: "\u{FF29}\u{FF27}\u{FF2E}" => "ign";
    n_zero_width: "ig\u{200B}nore" => "ignore";
    n_soft_hyphen: "ig\u{00AD}nore" => "ignore";
    n_bidi: "a\u{202E}b" => "ab";
    n_combining: "e\u{0301}x" => "ex";
    n_precomposed: "caf\u{00e9}" => "cafe";
    n_leet_mixed: "1gn0r3" => "ignore";
    n_leet_symbols: "p@$$w0rd" => "password";
    n_numbers_untouched: "top 5 in 15 minutes" => "top 5 in 15 minutes";
    n_spaced: "i g n o r e this" => "ignore this";
    n_dotted: "i.g.n.o.r.e" => "ignore";
    n_short_run_kept: "a b c" => "a b c";
    n_hyphen_between_letters: "read-only" => "readonly";
    n_hyphen_space_kept: "a - b" => "a - b";
    n_underscore: "send_email" => "send email";
    n_apostrophe: "don't" => "dont";
    n_curly_apostrophe: "won\u{2019}t" => "wont";
    n_star_split: "ig*nore" => "ignore";
    n_ligature: "\u{FB01}le" => "file";
    n_empty: "" => "";
}

macro_rules! skel {
    ($($n:ident: $a:expr => $b:expr;)*) => {$(
        #[test]
        fn $n() {
            assert_eq!(name_skeleton($a), $b);
        }
    )*};
}

skel! {
    sk_snake: "send_email" => "sendemaii";
    sk_camel: "sendEmail" => "sendemaii";
    sk_digit: "send_emai1" => "sendemaii";
    sk_cyr: "s\u{0435}nd_email" => "sendemaii";
    sk_kebab: "send-email" => "sendemaii";
}

#[test]
fn osa_identical() {
    assert_eq!(osa_distance("abc", "abc"), 0);
}
#[test]
fn osa_substitution() {
    assert_eq!(osa_distance("abc", "abd"), 1);
}
#[test]
fn osa_transposition() {
    assert_eq!(osa_distance("send", "sned"), 1);
}
#[test]
fn osa_insert_delete() {
    assert_eq!(osa_distance("email", "emails"), 1);
    assert_eq!(osa_distance("", "abc"), 3);
}
#[test]
fn osa_far() {
    assert!(osa_distance("send_email", "list_channels") > 3);
}
