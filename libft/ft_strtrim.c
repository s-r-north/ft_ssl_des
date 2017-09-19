/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/03/04 13:53:01 by snorth            #+#    #+#             */
/*   Updated: 2017/03/08 18:13:35 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strtrim(const char *s)
{
	int		i;
	int		len;
	char	*ret;

	if (s == NULL)
		return (NULL);
	while (*s == ' ' || *s == '\t' || *s == '\n')
		s++;
	len = 1;
	while (s[len] != 0)
		len++;
	while (s[--len] == ' ' || s[len] == '\t' || s[len] == '\n')
		;
	if (!(ret = ft_strnew(len + 1)))
		return (NULL);
	if (len == 1)
	{
		ret[0] = 0;
		return (ret);
	}
	i = -1;
	while (++i <= len)
		ret[i] = s[i];
	ret[i] = 0;
	return (ret);
}
