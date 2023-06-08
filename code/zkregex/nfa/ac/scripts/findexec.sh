# src: https://serverfault.com/questions/450122/how-to-find-any-file-that-is-an-executable-or-library
#find / -type f -name "*" -perm -111 -not -name "*.o" -not -name "*.so" -exec sh -c '
find / -type f -name "*.o" -not -path "/tmp/*" -not -path "/home/*" -not -path "/snap/*" -exec sh -c '
    case "$(head -n 1 "$1")" in
      ?ELF*) exit 0;;
      MZ*) exit 0;;
      #!*/ocamlrun*)exit0;;
    esac
exit 1
' sh {} \; -print

find / -type f -name "*"  -not -path "/tmp/*" -not -path "/home/*" -not -path "/snap/*" -perm -111 -exec sh -c '
    case "$(head -n 1 "$1")" in
      ?ELF*) exit 0;;
      MZ*) exit 0;;
      #!*/ocamlrun*)exit0;;
    esac
exit 1
' sh {} \; -print
