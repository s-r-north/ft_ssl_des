/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/28 17:53:05 by snorth            #+#    #+#             */
/*   Updated: 2017/03/03 16:03:11 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnstr(const char *big, const char *little, size_t len)
{
	size_t	i;
	size_t	j;
	int		place;

	if (ft_strlen(little) == 0)
		return ((char*)&big[0]);
	i = -1;
	while (big[++i] != 0 && i < len)
	{
		if (big[i] == little[0])
		{
			j = -1;
			place = i;
			while (little[++j] != 0 && big[i] == little[j] && i <= len)
				i++;
			if (little[j] == 0 && i <= len)
				return ((char*)&big[place]);
			else
				i = place;
		}
	}
	return (NULL);
}
