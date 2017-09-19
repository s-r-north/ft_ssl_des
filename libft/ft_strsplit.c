/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/03/03 21:53:23 by snorth            #+#    #+#             */
/*   Updated: 2017/03/09 13:08:02 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

static char	*splitter(const char *s, char c, size_t len, size_t i)
{
	char	*str;

	i = (long)i - (long)len < 0 ? 0 : i - len;
	str = (char*)malloc(sizeof(char) * len + 1);
	len = 0;
	while (s[i] != c && s[i] != 0)
		str[len++] = s[i++];
	str[len] = 0;
	return (str);
}

char		**ft_strsplit(const char *s, char c)
{
	size_t	i;
	size_t	len;
	size_t	strings;
	char	**ret;

	strings = ft_count_words(s, c);
	if (s == NULL || !(ret = (char**)malloc(sizeof(char*) * strings + 1)))
		return (NULL);
	i = -1;
	strings = -1;
	len = 0;
	while (++i <= ft_strlen(s))
	{
		if (s[i] != c && s[i] != 0)
			len++;
		if ((s[i] == c || s[i] == 0) && len > 0)
		{
			ret[++strings] = splitter(s, c, len, i);
			len = 0;
		}
	}
	ret[++strings] = 0;
	return (ret);
}
