mod parser;

pub fn parse_length(input: &str) -> usize {
    parser::length(input)
}
