    char text[2][256];
    int len = strlen(-=STRING=-[0]);
    //x用于循环向后查找分割字符并替换为\0，y用于指向第一个找到的不为分割字符的值（即前半部分字符串的首字符），然后x找到并指向第二次出现在分割字符后的值（即后半部分字符串的首字符）
    int x, y;
    for (x = 0, y = 0; x < len; x++)
    {
        if (-=STRING=-[x] == ' ' || -=STRING=-[x] == '\t' || -=STRING=-[x] == '=' || -=STRING=-[x] == ':') //用于将字符串一分为二的字符列表，空格，\t必须有，用于识别aaa = bbb的情况
        {
            -=STRING=-[x] = '\0';
            //识别头部多个分割字符的情况，并忽略多余的分割字符
            if (strlen(-=STRING=- + y) != 0)
            {
                //将头部的有效字符串（即前半部分字符串）拷贝下来
                strncpy(text[0], -=STRING=- + y, sizeof(text[0]));
                //判断后面的第二部分
                x++;
                while (x < len && (-=STRING=-[x] == ' ' || -=STRING=-[x] == '\t' || -=STRING=-[x] == '=' || -=STRING=-[x] == ':'))
                {
                    -=STRING=-[x] = '\0';
                    x++;
                }
                if (x < len)
                    strncpy(text[1], -=STRING=- + x, sizeof(text[1]));
                break;
            }
            y = x + 1;
        }
    }
    
    //对于“aaaa ”这样有前半部分，有分割字符，但没有后半部分的情况，代码可以识别并复制前半部分，后半不管
    //但是如果时“aaaa”这种有前半部分，但是没有跟随分割字符的情况，则无法复制。如需复制，则在for循环结尾加上
    /*
    
    //尾没有分割字符的情况，只有一个部分
    if (x == len - 1 && y != len)
    {
        strncpy(text[0], -=STRING=- + y, sizeof(text[0]));
    }
    
    */