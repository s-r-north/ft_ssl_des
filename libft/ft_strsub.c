/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsub.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/03/04 11:29:01 by snorth            #+#    #+#             */
/*   Updated: 2017/03/08 17:23:34 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strsub(const char *s, unsigned int start, size_t len)
{
	size_t	i;
	char	*ret;

	if (!(ret = ft_strnew(len)) || s == NULL)
		return (NULL);
	i = -1;
	while (++i < len)
		ret[i] = s[start++];
	while (i <= len)
		ret[i++] = 0;
	return (ret);
}
