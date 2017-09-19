/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_count_words.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/03/08 21:55:31 by snorth            #+#    #+#             */
/*   Updated: 2017/03/09 13:09:05 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_count_words(const char *s, char c)
{
	size_t	words;
	size_t	i;

	i = -1;
	words = 0;
	if (s == NULL)
		return (0);
	while (s[++i] != 0)
		if (s[i] != c && (s[i - 1] == c || i == 0))
			words++;
	return (words);
}
