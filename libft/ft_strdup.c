/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/27 16:16:19 by snorth            #+#    #+#             */
/*   Updated: 2017/03/08 17:22:22 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strdup(const char *s1)
{
	size_t	i;
	char	*ret;

	if (!(ret = ft_strnew(ft_strlen(s1))))
		return (NULL);
	i = -1;
	while (++i <= ft_strlen(s1))
		ret[i] = s1[i];
	ret[i] = 0;
	return (ret);
}
