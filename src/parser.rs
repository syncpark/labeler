use percent_encoding::percent_decode_str;

const OPTION_URL_DECODE: bool = false;
const OPTION_EXCLUDE_NUMERIC: bool = true;
const OPTION_REMOVE_DUPLICATES: bool = false;
// const OPTION_REMOVE_URL_ENCODE: bool = true;
const OPTION_TO_LOWERCASE: bool = true;
const OPTION_TOKEN_MIN_LENGTH: usize = 3;
const OPTION_REMOVE_HEXCODE: bool = true;
const OPTION_HEXCODE_MIN_LENGTH: usize = 20;
const OPTION_REMOVE_DOT_DIGIT: bool = true;

// characters treated as token
const TOKEN_CHARS: [char; 4] = ['.', '_', '-', '@'];

/*
const TOKEN_DELIMITERS: [char; 28] = [
    '/', '?', '&', '=', '[', ']', '\'', ';', ')', '(', '+', '*', ',', '<', '>', '\\', '\"', '|',
    '~', '{', '}', ':', '\t', '#', '!', ' ', '`', '$',
];
*/

#[must_use]
pub fn extract_tokens(s: &str) -> Vec<String> {
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    let mut begin: usize;
    let mut end: usize;
    let mut eof: bool = false;

    let mut chs = s.char_indices();
    loop {
        begin = 0;
        end = 0;

        loop {
            if let Some((idx, c)) = chs.next() {
                if c.is_alphanumeric() || TOKEN_CHARS.contains(&c) {
                    begin = idx;
                    break;
                }
                continue;
            }
            eof = true;
            break;
        }

        if !eof {
            loop {
                if let Some((idx, c)) = chs.next() {
                    end = idx;
                    if c.is_alphanumeric() || TOKEN_CHARS.contains(&c) {
                        continue;
                    }
                    break;
                }
                eof = true;
                break;
            }
        }

        if begin < end {
            if eof {
                pairs.push((begin, end + 1));
            } else {
                pairs.push((begin, end));
            }
        } /* else if s.len() > start {
              pairs.push((start, s.len()));
          }*/

        if eof {
            break;
        }
    }

    let mut v: Vec<String> = Vec::new();
    for (x, y) in &pairs {
        if let Some(s) = s.get(*x..*y) {
            let mut token = s.trim().to_string();
            if OPTION_URL_DECODE && token.contains('%') {
                token = percent_decode_str(&token).decode_utf8_lossy().to_string();
            }

            if OPTION_EXCLUDE_NUMERIC && check_numeric(s) {
                continue;
            }

            if OPTION_TO_LOWERCASE {
                token = token.to_lowercase();
            }

            if OPTION_REMOVE_DUPLICATES && v.contains(&token) {
                continue;
            }

            if token.len() < OPTION_TOKEN_MIN_LENGTH {
                continue;
            }

            if OPTION_REMOVE_HEXCODE && check_hexdigit(s) && (*y - *x) >= OPTION_HEXCODE_MIN_LENGTH
            {
                continue;
            }

            if OPTION_REMOVE_DOT_DIGIT && check_dotdigit(s) {
                continue;
            }

            // TODO:
            // - remove leading and trailing dot(.)

            v.push(token);
        }
    }
    v
}

fn check_numeric(x: &str) -> bool {
    let mut ch = x.chars();
    loop {
        if let Some(c) = ch.next() {
            if c.is_numeric() {
                continue;
            }
            return false;
        }
        return true;
    }
}

fn check_hexdigit(x: &str) -> bool {
    let mut ch = x.chars();
    loop {
        if let Some(c) = ch.next() {
            if c.is_ascii_hexdigit() {
                continue;
            }
            return false;
        }
        return true;
    }
}

fn check_dotdigit(x: &str) -> bool {
    let mut ch = x.chars();
    loop {
        if let Some(c) = ch.next() {
            if c.is_numeric() || c == '.' {
                continue;
            }
            return false;
        }
        return true;
    }
}
