/*______                                                ___            __        __
 /\__  _\                          __                  /\_ \          /\ \      /\ \
 \/_/\ \/    __   _ __    ___ ___ /\_\    ___      __  \//\ \         \_\ \___  \_\ \___
    \ \ \  /'__`\/\`'__\/' __` __`\/\ \ /' _ `\  /'__`\  \ \ \       /\___  __\/\___  __\
     \ \ \/\  __/\ \ \/ /\ \/\ \/\ \ \ \/\ \/\ \/\ \L\.\_ \_\ \_     \/__/\ \_/\/__/\ \_/
      \ \_\ \____\\ \_\ \ \_\ \_\ \_\ \_\ \_\ \_\ \__/.\_\/\____\        \ \_\     \ \_\
       \/_/\/____/ \/_/  \/_/\/_/\/_/\/_/\/_/\/_/\/__/\/_/\/____/         \/_/      \/_/

T++ é um terminal inspirado pelo Prompt de Comando do Windows, com o objetivo de adicionar mais comandos para ajudar mais o usuario.
Esse terminal tem todos os comandos do Prompt de Comandos do Windows + alguns outros comandos.
Só é permitido Windows 11 ou Windows 10
Feito com amor, carinho e dores de cabeça por Thiaguinho no C++11
 ____       __        __             _     _
/\  _`\    /\ \      /\ \          /' \  /' \
\ \ \/\_\  \_\ \___  \_\ \___     /\_, \/\_, \
 \ \ \/_/_/\___  __\/\___  __\     \/_/\ \/_/\ \
  \ \ \L\ \/__/\ \_/\/__/\ \_/       \ \ \ \ \ \
   \ \____/   \ \_\     \ \_\         \ \_\ \ \_\
    \/___/     \/_/      \/_/          \/_/  \/_/

Codigo inteiramente feito em C++11 usando MinGW */

#include <iostream> // se nao tiver nao roda
#include <cstdlib>
#include <fstream>
#include <string>
#include <locale>
#include <cstdio>
#include <memory>
#include <array>
#ifndef COMMON_LVB_UNDERSCORE
#define COMMON_LVB_UNDERSCORE 0x8000
#endif

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#else
#include <unistd.h>

#include <limits.h>
#endif

// LIBS HANDLE
#include "configs/libs/json.hpp"      // pra ver e editar jsons
#include "configs/libs/termcolor.hpp" // colocar corzinhas :))))

using namespace std; // so pra eu nao ter que ficar colocando a misera de "std::" toda hora, é chato
using json = nlohmann::json;

bool os_check;   // Verificacoes
bool curl_check; // Verificacoes
bool canEnter;   // Verificacoes

string server_version = "https://raw.githubusercontent.com/ThiagoBel/versions_apps/refs/heads/main/terminalpp/vers.txt"; // ve as atualizacoes
string server_docs = "https://raw.githubusercontent.com/ThiagoBel/versions_apps/refs/heads/main/terminalpp/doc.txt";     // os docs

string caminho_do_tpp;                  // caminho do Terminal++
string nameapp = "T++";                 // Apenas o nome do bagulho
string sub_this_version = "Terminal++"; // key para testes
string this_version = "228115";         // versao do teu terminal que funciona da seguinte forma:
// primeiro comeca com o primeiro digito do ano
// depois com o primeiro digito do dia
// depois o segundo digito do dia
// depois o primeiro e segundo digito do mes
// por ultimo, o ultimo digito do ano

bool osterm_enabled = true; // bool para ver se pode usar os comandos do OS do usuario

vector<string> split_and(const string &str) // deixa tu usar o "&&&&" :)
{
    vector<string> comandos;
    string temp;
    bool dentroAspas = false;

    for (size_t i = 0; i < str.size(); i++)
    {
        char c = str[i];

        if (c == '"')
        {
            dentroAspas = !dentroAspas;
            temp += c;
            continue;
        }

        if (!dentroAspas &&
            c == '&' &&
            i + 3 < str.size() &&
            str[i + 1] == '&' &&
            str[i + 2] == '&' &&
            str[i + 3] == '&')
        {
            comandos.push_back(temp);
            temp.clear();
            i += 3;
        }
        else
        {
            temp += c;
        }
    }

    if (!temp.empty())
        comandos.push_back(temp);

    return comandos;
}

// Codigos de erros que podem aparecer
const vector<pair<string, string>> coisoss = {
    {"Erro. Caminho não encontrado", "2cne5"},
    {"Erro. JSON não foi salvo", "2jns5"},
    {"Erro. Terminal++ não tem suporte para seu sistema operacional", "2sst5"},
    {"Erro. Seu sistema operacional não tem suporte para esse comando", "2ssc5"},
    {"Erro. Um erro desconhecido aconteceu", "2emd5"},
    {"Erro. Arquivo temporario nao foi deletado corretamente", "2atd5"},
    {"Erro. Erro na criação do arquivo", "2anc5"},
    {"Erro. Não foi possível abrir o arquivo", "2nfa5"},
    {"Erro. ARG desconhecida", "2amd5"},
    {"Erro. Valor não permitido", "2vnp5"},
    {"Erro. Comando desconhecido", "2cnc5"},
    {"Erro. Erro no caminho", "2enc5"},
    {"Erro. Esse comando só funciona com permissão do administrador", "2coa5"},
    {"Erro. Sem o CURL o Terminal++ não irá funcionar", "2soc5"},
    {"Erro. Parâmetros insuficientes", "2par5"},
    {"Erro. Comando 'say' inválido, faltando ')'", "2cds5"},
    {"Erro.", "2soe5"},
    {"?", "2mne5"}};

string errors(const string &value)
{
    for (auto &p : coisoss)
    {
        if (p.second == value)
        {
            return p.first;
        }
    }

    return "Erro. Erro não encontrado.";
} // funcao pra chamar os erros e mostrar ele

typedef LONG(WINAPI *RtlGetVersionPtr)(OSVERSIONINFOEXW *);

string CHECK_WINDOWS_VERSION() // mds
{
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod)
    {
        RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (fxPtr != nullptr)
        {
            OSVERSIONINFOEXW osInfo = {0};
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);
            if (fxPtr(&osInfo) == 0)
            { // SUCESSOOOOOOOOOOOOOOOOOOO
                if (osInfo.dwMajorVersion == 10)
                {
                    return "Win10+";
                }
                else
                {
                    return "Win10-";
                }
            }
        }
    }
    return "Versão desconhecida";
}
void show_all_errors()
{
    for (auto &p : coisoss)
    {
        cout << "ID: " << termcolor::cyan << p.second << termcolor::reset << "   |   MSG: " << termcolor::cyan << p.first << termcolor::reset << endl;
    }
} // preciso nem falar, é so ler o nome da function

json infos_user;

string PATH()
{
#ifdef _WIN32
    char buffer[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, buffer))
        return string(buffer);
    else
        return errors("2mne5");
#else
    char buffer[PATH_MAX];
    if (getcwd(buffer, sizeof(buffer)))
        return string(buffer);
    else
        return errors("2mne5");
#endif
} // Isso é so pra literalmente mostrar o caminho onde ta

bool CURL_CHECK()
{
    if (system("curl.exe --version >nul 2>&1") == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool IS_WINDOWS()
{
    const char *windir = getenv("WINDIR");
    return windir != nullptr;
} // ve se é windows

string USER_CHECK()
{
#ifdef _WIN32
    return getenv("USERNAME");
#else
    return getenv("USER");
#endif
} // mostra o teu nome😈

bool check_total()
{
    if (IS_WINDOWS() == true)
    {
        os_check = true; // WOOW
    }
    if (IS_WINDOWS() != true)
    {
        cout << termcolor::red << errors("2sst5") << termcolor::reset << "\n"; // se nao for windows, pega o beco
    }

    if (CURL_CHECK() == true)
    {
        curl_check = true;
    }
    else
    {
        cout << termcolor::red << errors("2soc5") << termcolor::reset << "\n"; // se nao tiver curl, ele da erro
    }

    if (curl_check == true && os_check == true)
    {
        canEnter = true;
        return true;
    }
    else
    {
        canEnter = false;
        return false;
    }
} // serve pra verificar tudo pra ver se tu pode entrar ou nao

bool CHECK_ADMIN()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

void print_error(const string &msg)
{
    cout << termcolor::red << msg << termcolor::reset << endl;
}

void print_warn(const string &msg)
{
    cout << termcolor::yellow << msg << termcolor::reset << endl;
}

void print_sys(const string &msg)
{
    cout << termcolor::blue << msg << termcolor::reset << endl;
}

void print_basic(const string &msg)
{
    cout << msg << endl;
}

void print_green(const string &msg)
{
    cout << termcolor::green << msg << termcolor::reset << endl;
}

bool change_dir(const string &path)
{
    return SetCurrentDirectoryA(path.c_str()); // ignora
}

string to_lower(const string &texto) // transforma todo texto em minusculo
{
    string resultado = texto;
    for (char &c : resultado)
    {
        c = tolower((unsigned char)c);
    }
    return resultado;
}

string CHECK_UPDATES()
{
    string windowsVersion = CHECK_WINDOWS_VERSION();

    if (windowsVersion != "Win10+")
    {
        cerr << errors("2ssc5") << endl;
        return "";
    }

    string result;
    array<char, 128> buffer;

    string command = "curl -s --ssl-no-revoke " + server_version;

#ifdef _WIN32
    FILE *pipe = _popen(command.c_str(), "r");
#else
    FILE *pipe = popen(command.c_str(), "r");
#endif

    if (!pipe)
    {
        cerr << errors("2emd5") << endl;
        return "";
    }

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
    {
        result += buffer.data();
    }

#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif

    // remove quebra de linha do final
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();

    return result;
}

string CHECK_EXTERNAL_INFOS(const string &website) // preciso nem dizer pra q serve
{
    string windowsVersion = CHECK_WINDOWS_VERSION();

    if (windowsVersion != "Win10+") // so windows10 pa cima
    {
        cerr << errors("2ssc5") << endl;
        return "";
    }

    string result;
    array<char, 128> buffer;

    string command = "curl -s --ssl-no-revoke " + website;

#ifdef _WIN32
    FILE *pipe = _popen(command.c_str(), "r");
#else
    FILE *pipe = popen(command.c_str(), "r");
#endif

    if (!pipe)
    {
        cerr << errors("2emd5") << endl;
        return "";
    }

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
    {
        result += buffer.data();
    }

#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif

    return result;
}

void puxarocamindobagulho(string &diretorio) // puxa o caminho do terminal++ pro diretorio (   não sei explicar >:[   )
{
    char caminho[MAX_PATH];

    GetModuleFileNameA(NULL, caminho, MAX_PATH);

    diretorio = caminho;

    size_t pos = diretorio.find_last_of("\\/");
    diretorio = diretorio.substr(0, pos);
}

void CT_DIR(string pathh) // é o dir do bagui
{
    string search = pathh + "\\*";

    WIN32_FIND_DATAA data;
    HANDLE hFind = FindFirstFileA(search.c_str(), &data);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        print_error(errors("2enc5"));
        return;
    }

    do
    {
        string nome = data.cFileName;

        if (nome == "." || nome == "..")
            continue;

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            cout << termcolor::bright_red << "<PASTA> ---->     " << termcolor::reset << termcolor::bright_cyan << nome << termcolor::reset << endl;
        else
        {
            cout << termcolor::bright_red << "<ARQUIVO> -->     " << termcolor::reset << termcolor::bright_cyan << nome << termcolor::reset << endl;
        }

    } while (FindNextFileA(hFind, &data));

    FindClose(hFind);
}

void botarnopathhhh(const string &novoPath) // pra colocar algo no path do sistema
{
    if (GetFileAttributesA(novoPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        print_error("Path inválido"); // erro desgracado
        return;
    }

    HKEY hKey;

    if (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
            0,
            KEY_READ | KEY_SET_VALUE,
            &hKey) != ERROR_SUCCESS)
    {
        print_error("Erro ao abrir registro (rode como administrador)"); // erro
        return;
    }

    char buffer[32767];
    DWORD bufferSize = sizeof(buffer);
    string pathAtual;

    if (RegQueryValueExA(hKey, "Path", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
    {
        pathAtual = buffer;
    }

    if (pathAtual.find(novoPath) != string::npos)
    {
        print_error("Esse path já existe no sistema"); // erro gostoso
        RegCloseKey(hKey);
        return;
    }

    pathAtual += ";" + novoPath;

    if (RegSetValueExA(hKey, "Path", 0, REG_EXPAND_SZ,
                       (BYTE *)pathAtual.c_str(), pathAtual.length() + 1) != ERROR_SUCCESS)
    {
        print_error("Erro ao salvar PATH do sistema"); // erro errado
        RegCloseKey(hKey);
        return;
    }

    RegCloseKey(hKey);

    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        (LPARAM) "Environment", SMTO_ABORTIFHUNG, 1000, NULL);
}

void removeropathhhh(const string &pathRemover) // remove algo do path do sistema
{
    HKEY hKey;

    if (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
            0,
            KEY_READ | KEY_SET_VALUE,
            &hKey) != ERROR_SUCCESS)
    {
        print_error("Erro ao abrir registro (rode como administrador)");
        return;
    }

    char buffer[32767];
    DWORD bufferSize = sizeof(buffer);
    string pathAtual;

    if (RegQueryValueExA(hKey, "Path", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) != ERROR_SUCCESS)
    {
        print_error("Erro ao ler PATH do sistema");
        RegCloseKey(hKey);
        return;
    }

    pathAtual = buffer;

    size_t pos = pathAtual.find(pathRemover);

    if (pos == string::npos)
    {
        print_error("Esse path não existe no sistema");
        RegCloseKey(hKey);
        return;
    }

    size_t inicio = pos;
    size_t fim = pos + pathRemover.length();

    if (inicio > 0 && pathAtual[inicio - 1] == ';')
        inicio--;

    if (fim < pathAtual.length() && pathAtual[fim] == ';')
        fim++;

    pathAtual.erase(inicio, fim - inicio);

    if (RegSetValueExA(hKey, "Path", 0, REG_EXPAND_SZ,
                       (BYTE *)pathAtual.c_str(), pathAtual.length() + 1) != ERROR_SUCCESS)
    {
        print_error("Erro ao salvar PATH do sistema");
        RegCloseKey(hKey);
        return;
    }

    RegCloseKey(hKey);

    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        (LPARAM) "Environment", SMTO_ABORTIFHUNG, 1000, NULL);
}

bool verify_path_TPP(const string &caminho) // veirifica se o path do terminal++ tá no sistema
{
    HKEY hKey;

    if (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
            0,
            KEY_READ,
            &hKey) != ERROR_SUCCESS)
    {
        return false;
    }

    char buffer[32767];
    DWORD bufferSize = sizeof(buffer);

    string pathAtual;

    if (RegQueryValueExA(hKey, "Path", nullptr, nullptr,
                         (LPBYTE)buffer, &bufferSize) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);

    pathAtual = buffer;

    size_t pos = pathAtual.find(caminho);
    while (pos != string::npos)
    {
        bool antes = (pos == 0 || pathAtual[pos - 1] == ';');
        bool depois = (pos + caminho.size() == pathAtual.size() ||
                       pathAtual[pos + caminho.size()] == ';');

        if (antes && depois)
            return true;

        pos = pathAtual.find(caminho, pos + 1);
    }

    return false;
}

bool verify_pasta_TPP(const string &caminho)
{
    string pasta = caminho + "\\Configs";

    DWORD attr = GetFileAttributesA(pasta.c_str());

    if (attr == INVALID_FILE_ATTRIBUTES)
        return false;

    return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

string tamanhodearquivos(const string &caminho) // mostra o tamanho de um arquivo selecionado
{
    WIN32_FILE_ATTRIBUTE_DATA info;

    if (!GetFileAttributesExA(caminho.c_str(), GetFileExInfoStandard, &info))
        return "Erro";

    LARGE_INTEGER tamanho;
    tamanho.HighPart = info.nFileSizeHigh;
    tamanho.LowPart = info.nFileSizeLow;

    double bytes = static_cast<double>(tamanho.QuadPart);  // mostra em bytes
    double tamanhoKB = bytes / 1024.0;                     // mostra em kb
    double tamanhoMB = bytes / (1024.0 * 1024.0);          // mostra em mb
    double tamanhoGB = bytes / (1024.0 * 1024.0 * 1024.0); // mostra em gb

    ostringstream ss;

    ss << fixed << setprecision(2);
    ss << bytes << " bytes | ";
    ss << tamanhoKB << " KB | ";
    ss << tamanhoMB << " MB | ";
    ss << tamanhoGB << " GB";

    return ss.str();
}

void executar_comando(const string &userr);
void executar_comando_arquivo(const string &caminho);

void executar_comando_arquivo(const string &caminho)
{
    const string ext = ".tplusx";
    string arquivo = caminho;

    if (arquivo.size() < ext.size() ||
        arquivo.substr(arquivo.size() - ext.size()) != ext) // se nao tiver ".tplusx" ele msm bota
    {
        arquivo += ext;
    }

    ifstream arquivov(arquivo);

    if (!arquivov.is_open())
    {
        print_error(errors("2nfa5"));
        return;
    }

    string linha;
    while (getline(arquivov, linha))
    {
        size_t pos = linha.find("#//"); // comentario
        if (pos != string::npos)
            linha = linha.substr(0, pos);

        auto limpar = [](string &s)
        {
            while (!s.empty() && isspace((unsigned char)s.front()))
                s.erase(s.begin());
            while (!s.empty() && isspace((unsigned char)s.back()))
                s.pop_back();
        };
        limpar(linha);

        if (!linha.empty())
            executar_comando(linha);
    }
}

void executar_comando(const string &userr)
{
    string user;
    user = to_lower(userr);
    if (user == "exit")
    {
        exit(0); // tive que colocar pq a misera do 'system()' nao bota o exit por padrao
    }
    else if (user == "killtpp")
    {
        TerminateProcess(GetCurrentProcess(), 0);
    }
    else if (user.size() >= 3 && user.substr(0, 3) == "cd ")
    {
        string newPath = user.substr(3);
        if (!change_dir(newPath))
        {
            cout << termcolor::red << errors("2cne5") << termcolor::reset << "\n";
        }
        // botei isso pq ia ter na teoria pra linux e windows, mas tirei linux, ai ficou msm
    }
    else if (user == "all_errors" || user == "check_errors" || user == "errors")
    {
        show_all_errors(); // mostra os erros que tem no bagui
    }
    else if (user == "credits") // creditos
    {
        cout << termcolor::red << "Thiaguinho - Criador do Terminal++" << termcolor::reset << endl;                      // eu
        cout << termcolor::red << "nlohmann - Criador da biblioteca <json.hpp>" << termcolor::reset << endl;             // muito obrigado criador da biblioteca json que serve pra ler os json, valeu
        cout << termcolor::red << "Ihor Kalnytskyi - Criador da biblioteca <termcolor.hpp>" << termcolor::reset << endl; // muito obrigado criador dessa linda e maravilhosa biblioteca pra colocar cor :)))
    }
    else if (user.size() >= 2 && user.substr(0, 2) == "^>")
    {
        string coisoss = user.substr(2);
        system(coisoss.c_str());
        // serve pra garantir que vai rodar pelo teu sistema operacional
    }
    else if (user.size() >= 5 && user.substr(0, 5) == "open ")
    {
        string appname = user.substr(5);
        system(("start " + appname).c_str());
        // ignora, ia ter pra linux, mas tirei suporte pra linux, ai fiquei com preguiça de tirar
        // o comando agr so roda windows
    }
    else if (user.size() >= 4 && user.substr(0, 4) == "say ") // ele diz algo
    {
        string aaa = user.substr(4);
        size_t pos = aaa.find("%stop_say%");
        if (pos != string::npos)
        {
            aaa = aaa.substr(0, pos);
        }
        cout << aaa << endl;
    }
    else if (user == "check_updates" || user == "updates") // verifica se esta desatualizado ou nao
    {
        if (CHECK_UPDATES() == this_version)
        {
            cout << termcolor::bright_yellow << "Esta atualizado (" << this_version << ")" << termcolor::reset << endl;
        }
        else
        {
            cout << termcolor::bright_yellow << "Esta desatualizado\nSua versao: " << this_version << "\nNova versao: " << CHECK_UPDATES() << termcolor::reset << endl;
        }
    }
    else if (user == "check_key" || user == "key") // mostra a key (sub_this_version)
    {
        print_sys(sub_this_version);
    }
    else if (user == "check_docs" || user == "docs") // mostra os docs
    {
        cout << CHECK_EXTERNAL_INFOS(server_docs) << endl;
    }
    else if (user == "check_admin" || user == "check_adm" || user == "adm" || user == "admin")
    {
        if (CHECK_ADMIN() == true)
        {
            print_sys("Está rodando como admin");
        }
        else
        {
            print_sys("Não está rodando como admin");
        }
    }
    else if (user.size() >= 15 && user.substr(0, 15) == "check_info_ext ") // verifica infos externas
    {
        string aaaa = user.substr(15);
        cout << termcolor::blue << CHECK_EXTERNAL_INFOS(aaaa) << termcolor::reset << endl;
    }
    else if (user.size() >= 4 && user.substr(0, 4) == "ext ") // mesma coisa do de cima
    {
        string aaaa = user.substr(4);
        cout << termcolor::blue << CHECK_EXTERNAL_INFOS(aaaa) << termcolor::reset << endl;
    }
    else if (user == "check_tpp" || user == "check_t++" || user == "check_terminal" || user == "check_terminal++")
    {
        cout << termcolor::blue << caminho_do_tpp << termcolor::reset << endl;
    }
    else if (user.size() > 4 && user.substr(0, 4) == "otc ")
    {
        string aa = user.substr(4);
        if (aa == "f" || aa == "false")
        {
            osterm_enabled = false;
        }
        else if (aa == "t" || aa == "true")
        {
            osterm_enabled = true;
        }
        else
        {
            print_error(errors("2vnp5"));
        }
    }
    else if (user == "dir")
    {
        CT_DIR(PATH());
    }
    else if (user == "&path")
    {
        if (CHECK_ADMIN() == true)
        {
            botarnopathhhh(caminho_do_tpp);
        }
        else
        {
            print_error(errors("2coa5"));
        }
    }
    else if (user == "&rpath")
    {
        if (CHECK_ADMIN() == true)
        {
            removeropathhhh(caminho_do_tpp);
        }
        else
        {
            print_error(errors("2coa5"));
        }
    }
    else if (user.size() > 9 && user.substr(0, 9) == "del_path ")
    {
        string coooso = user.substr(9);
        if (CHECK_ADMIN() == true)
        {
            removeropathhhh(coooso);
        }
        else
        {
            print_error(errors("2coa5"));
        }
    }
    else if (user.size() > 9 && user.substr(0, 9) == "add_path ")
    {
        string coooso = user.substr(9);
        if (CHECK_ADMIN() == true)
        {
            botarnopathhhh(coooso);
        }
        else
        {
            print_error(errors("2coa5"));
        }
    }
    else if (user == "verify_tpp" || user == "verify_t++" || user == "verify_terminal" || user == "verify_terminalpp" || user == "verificy_terminal++")
    {
        string pathdotpp = "Path do Terminal++";
        string configsdotpp = "Configs do Terminal++";

        if (verify_path_TPP(caminho_do_tpp) == true)
        {
            print_green(pathdotpp + ": TRUE");
        }
        else
        {
            print_error(pathdotpp + ": FALSE");
        }
        if (verify_pasta_TPP(caminho_do_tpp) == true)
        {
            print_green(configsdotpp + ": TRUE");
        }
        else
        {
            print_error(configsdotpp + ": FALSE");
        }
    }
    else if (user.size() > 11 && user.substr(0, 11) == "check_size ")
    {
        string caminhouu = user.substr(11);
        print_sys(tamanhodearquivos(caminhouu));
    }
    else if (user.size() > 5 && user.substr(0, 5) == "exec ")
    {
        string oqqq = user.substr(5);
        executar_comando_arquivo(oqqq);
    }
    else
    {
        if (osterm_enabled == true)
        {
            system(user.c_str()); // todos os comandos do teu sistema operacional
        }
        else
        {
            print_error(errors("2cnc5") + ", use: \"otc true\" para habilitar a funcionalidade de usar comandos do sistema operacional (OS)"); // da erro se nao tiver ativado
        }
    }
}

// o main do C++ :)
int main(int argc, char *argv[])
{
    puxarocamindobagulho(caminho_do_tpp);
    if (argc > 1) // args
    {
        // args é pra tu poder colocar no terminal por exemplo "Terminal++ --version" sem executar todo o codiguin
        string arg = argv[1];

        if (arg == "--version") // mostra a versao do terminal
        {
            cout << "Terminal++ " << this_version << endl;
            if (argc > 2)
            {
                string sub = argv[2];

                if (sub == "-s") // ve pelo "servidor" (raw dp github)
                {
                    if (CHECK_UPDATES() == this_version)
                    {
                        cout << termcolor::bright_yellow << "Esta atualizado (" << this_version << ")" << termcolor::reset << endl;
                    }
                    else
                    {
                        cout << termcolor::bright_yellow << "Esta desatualizado\nSua versao: " << this_version << "\nNova versao: " << CHECK_UPDATES() << termcolor::reset << endl;
                    }
                }
                else if (sub == "-k") // key
                {
                    print_sys(sub_this_version);
                }
            }
            return 0;
        }
        else if (arg == "--about") // mostra a descricao do terminal
        {
            cout << "Terminal++ ou T++ é um terminal escrito em C++11 e criado por um brasileiro com o objetivo de ser um terminal muito bom e poderoso para o Windows." << endl;
            return 0;
        }
        else if (arg == "--enabled") // mostra se consegue usar o terminal
        {
            if (check_total() == true)
            {
                print_green("true");
            }
            else if (check_total() == false)
            {
                print_error("false");
                cout << "false" << endl;
            }
            else
            {
                print_error(errors("2vnp5"));
                return 1;
            }
            return 0;
        }
        else if (arg == "--check") // mostra o caminho do terminal
        {
            cout << termcolor::blue << caminho_do_tpp << termcolor::reset << endl;
        }
        else if (arg == "--size") // mostra o tamanho do terminal
        {
            char exe[MAX_PATH];
            GetModuleFileNameA(NULL, exe, MAX_PATH);

            ifstream f(exe, ios::binary | ios::ate);
            auto tamanho = f.tellg();

            string unidade = "bytes"; // WOW, É EM BAITES
            double valor = tamanho;

            if (argc > 2)
            {
                string sub = argv[2];
                if (sub == "-kb")
                {
                    valor = tamanho / 1024.0;
                    unidade = "KB";
                } // calcula pra kb
                else if (sub == "-mb")
                {
                    valor = tamanho / (1024.0 * 1024);
                    unidade = "MB";
                } // calcula pra mb
                else if (sub == "-gb")
                {
                    valor = tamanho / (1024.0 * 1024 * 1024);
                    unidade = "GB";
                } // calcula pra giga
                else if (sub == "-by")
                {
                    valor = tamanho;
                    unidade = "bytes";
                } // nem calcula
            }

            cout << valor << " " << unidade << endl;
            return 0;
        }
        else if (arg == "--docs") // mostra o doc do terminal
        {
            print_sys(CHECK_EXTERNAL_INFOS(server_docs));
            return 0;
        }
        else if (arg == "--cie") // mostra informacoes externas (ex: raws do github)
        {
            if (argc > 2)
            {
                string sub = argv[2];
                cout << termcolor::green << CHECK_EXTERNAL_INFOS(sub) << termcolor::reset << endl;
            }
            else
            {
                print_error("Nenhum comando fornecido");
                return 1;
            }
            return 0;
        }
        else if (arg == "--ut") // usar comandos do Terminal++ por fora
        {
            if (argc > 2)
            {
                string comando;

                for (int i = 2; i < argc; i++)
                {
                    comando += argv[i];

                    if (i + 1 < argc)
                        comando += " ";
                }

                executar_comando(comando);
            }
            else
            {
                print_error("Nenhum comando fornecido");
                return 1;
            }
            return 0;
        }
        else if (arg == "--itl") // coisas inuteis
        {
            if (argc > 2)
            {
                string sub = argv[2];
                if (sub == "-faces") // gera rostinhos
                {
                    srand(time(0));

                    const char *arr1[] = {">", "<"};                                                         // sombracelha
                    const char *arr2[] = {":", ";", "="};                                                    // olho
                    const char *arr3[] = {")", "(", "()", "[]", "]", "[", ">", "<", "D", "P", "3", "/", ""}; // boca

                    string resultado;

                    if (rand() % 2 == 0)
                    {
                        int i1 = rand() % 3;
                        resultado += arr1[i1];
                    }

                    int i2 = rand() % 3;
                    int i3 = rand() % (sizeof(arr3) / sizeof(arr3[0]));

                    resultado += arr2[i2];
                    resultado += arr3[i3];

                    cout << resultado << endl;
                }
                else 
                {
                    print_error(errors("2amd5"));
                    return 1;
                }
            }
            return 0;
        }
        else
        {
            print_error(errors("2amd5"));
            return 1;
        }
    }
    check_total(); // verifica tudo

    if (canEnter) // ve se pode entrar
    {
        system("title Terminal++");  // muda o titulo do terminal (nem precisa mas lgl)
        SetConsoleOutputCP(CP_UTF8); // Muda a fonte (nem precisa mas melhor colocar)
        if (CHECK_ADMIN() == true)
        {
            cout << termcolor::red << R"(  ______  __    __   __   _______       ___       _______   ______    __  
 /      ||  |  |  | |  | |       \     /   \     |       \ /  __  \  |  | 
|  ,----'|  |  |  | |  | |  .--.  |   /  ^  \    |  .--.  |  |  |  | |  | 
|  |     |  |  |  | |  | |  |  |  |  /  /_\  \   |  |  |  |  |  |  | |  | 
|  `----.|  `--'  | |  | |  '--'  | /  _____  \  |  '--'  |  `--'  | |__| 
 \______| \______/  |__| |_______/ /__/     \__\ |_______/ \______/  (__) 
                                                                            
Você está no modo administrador, se você usar comandos errados, pode acabar destruindo seu computador, faça isso para ter uma chance menos de danificar seu computador:

1. Evite comandos que crie arquivos ou remove arquivos.
2. Se alguem pedir para você colocar tal comando aqui, desconfie.
3. Troque de modo só se você não for usar comandos avançados e que precisam de administrador.)"
                 << termcolor::reset << endl;
        }

        while (true)
        {
            cout << nameapp << " " << PATH() << ": ";
            string entrada;
            getline(cin, entrada);

            vector<string> comandos = split_and(entrada);

            for (string &cmd : comandos) // Executa cada comando separado
            {
                cmd.erase(0, cmd.find_first_not_of(" "));
                cmd.erase(cmd.find_last_not_of(" ") + 1);

                executar_comando(cmd); // executa o comando (uau)
            }
        }
    }
    return 0; // se terminar tudo okei retorna 0, que significa que deu certo :)
}
// cabou"