use nom;

#[derive(Debug, Fail, PartialEq)]
pub enum ErrorEnum {
    #[fail(display = "Some I/O Error: {:?}", error)]
    IOError {
        error: ::std::io::ErrorKind,
    },
   #[fail(display = "Nom Error: {:?}", error)]
    NomError {
        error: nom::ErrorKind
    },
    #[fail(display = "Nom Failure: {:?}", error)]
    NomFailure {
        error: nom::ErrorKind
    },
    #[fail(display = "Nom InComplete: {:?}", error)]
    NomInComplete {
        error: nom::Needed
    },
    #[fail(display = "Utf8Error: {:?}", error)]
    Utf8Error {
        error: ::std::str::Utf8Error
    },
    #[fail(display = "Utf8Error: {:?}", error)]
    MyError {
        error: String
    }
}

impl From<::std::io::Error> for ErrorEnum {
    fn from(error: ::std::io::Error) -> Self {
        ErrorEnum::IOError { error: error.kind() }
    }
}

impl From<nom::Err<&[u8]>> for ErrorEnum {
    fn from(error: nom::Err<&[u8]>) -> Self {
        match error {
            nom::Err::Error(e) => ErrorEnum::NomError { error: e.into_error_kind() },
            nom::Err::Failure(e) => ErrorEnum::NomFailure { error: e.into_error_kind() },
            nom::Err::Incomplete(e) => ErrorEnum::NomInComplete { error: e },
        }
    }
}

impl From<::std::str::Utf8Error> for ErrorEnum {
    fn from(error: ::std::str::Utf8Error) -> Self {
        ErrorEnum::Utf8Error { error: error }
    }
}

impl From<String> for ErrorEnum {
    fn from(error: String) -> Self {
        ErrorEnum::MyError { error: error }
    }
}
