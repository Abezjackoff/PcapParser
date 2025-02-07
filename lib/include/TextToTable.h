#ifndef TEXT_TO_TABLE_H
#define TEXT_TO_TABLE_H

#include <vector>
#include <string>

class TextToTable
{
public:
    void reset()                        { table.clear(); maxRowLen = 0; formatted = false; }
    void new_row()                      { table.push_back(std::vector<std::string>{}); }
    void add_cell(const std::string& s) { table.back().push_back(" " + s + " "); }
    std::string print()
    {
        if (!formatted) format();
        std::string s;
        std::string rowStr;
        std::string horLine;
        for (auto& row : table){
            for (auto& cell : row){
                horLine.append("+").append(std::string(cell.size(), '-'));
            }
            horLine.append("+");
            for (int i = 0; i < rowStr.size() && i < horLine.size(); i++){
                if (rowStr[i] == '|') horLine[i] = '+';
            }
            s.append(horLine).append("\n");
            horLine.clear();
            rowStr.clear();
            for (auto& cell : row){
                rowStr.append("|").append(cell);
            }
            rowStr.append("|");
            s.append(rowStr).append("\n");
        }
        horLine.append("+").append(std::string(maxRowLen - 2, '-')).append("+");
        for (int i = 0; i < rowStr.size() && i < horLine.size(); i++){
                if (rowStr[i] == '|') horLine[i] = '+';
        }
        s.append(horLine);
        return s;
    }
private:
    void format()
    {
        maxRowLen = 0;
        for (auto& row : table){
            if (row.empty()) row.push_back("");
            int len = 1;
            for (auto& cell : row)len += cell.size() + 1;
            rowLen.push_back(len);
            maxRowLen = std::max(maxRowLen, len);
        }
        for (int i = 0; i < table.size(); i++){
            int nSpaces     = (maxRowLen - rowLen[i]) / table[i].size();
            int nSpacesRem  = (maxRowLen - rowLen[i]) % table[i].size();
            int rem = nSpacesRem;
            for (auto& cell : table[i]){
                std::string lSpaces = std::string(nSpaces / 2 + nSpaces % 2, ' ');
                std::string rSpaces = std::string(nSpaces / 2, ' ');
                cell = lSpaces.append(cell).append(rSpaces);
                if (rem){
                    cell.append(" ");
                    rem--;
                }
            }
        }
        formatted = true;
    }

    std::vector<std::vector<std::string>> table;
    std::vector<int> rowLen;
    int maxRowLen {};
    bool formatted {};
};

#endif
